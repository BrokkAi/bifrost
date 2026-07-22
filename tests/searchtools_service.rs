use brokk_bifrost::{
    AnalyzerConfig, FilesystemProject, Language, Project, SearchToolsService,
    SearchToolsServiceErrorCode, WorkspaceAnalyzer, scoped_project::create_scoped_service,
    searchtools::SCAN_USAGES_RESPONSE_BUDGET_BYTES, searchtools_render::RenderOptions,
};
mod common;
use common::{InlineTestProject, line_of};
use git2::{Repository, Signature};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

fn assert_workspace_path(value: &Value, expected: &Path) {
    let actual = value["workspace_path"]
        .as_str()
        .expect("workspace_path string");
    assert_eq!(
        Path::new(actual)
            .canonicalize()
            .expect("canonicalize actual workspace path"),
        expected
            .canonicalize()
            .expect("canonicalize expected workspace path")
    );
}

fn array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0)
}

fn status_count(value: &Value, status: &str) -> usize {
    result_status_count(value, &[status])
}

fn resolved_scan_count(value: &Value) -> usize {
    result_status_count(
        value,
        &[
            "found",
            "verified_absent",
            "unverified_absent",
            "too_many_callsites",
        ],
    )
}

fn result_status_count(value: &Value, statuses: &[&str]) -> usize {
    results(value)
        .iter()
        .filter(|item| {
            item["status"]
                .as_str()
                .is_some_and(|s| statuses.contains(&s))
        })
        .count()
}

fn results(value: &Value) -> &[Value] {
    value["results"].as_array().expect("results array")
}

fn only_result(value: &Value) -> &Value {
    let results = results(value);
    assert_eq!(1, results.len(), "payload: {value}");
    &results[0]
}

#[test]
fn service_allows_concurrent_read_only_calls() {
    let service = Arc::new(SearchToolsService::new_without_semantic_index(fixture_root()).unwrap());
    let calls = [
        (
            "search_symbols",
            r#"{"patterns":["A"],"include_tests":true,"limit":5}"#,
        ),
        ("get_symbol_sources", r#"{"symbols":["A.method2"]}"#),
        ("get_summaries", r#"{"targets":["A.java"]}"#),
        (
            "most_relevant_files",
            r#"{"seed_file_paths":["A.java"],"limit":5}"#,
        ),
    ];

    let handles: Vec<_> = (0..16)
        .map(|index| {
            let service = Arc::clone(&service);
            let (tool, args) = calls[index % calls.len()];
            thread::spawn(move || {
                let payload = service.call_tool_json(tool, args).unwrap();
                serde_json::from_str::<Value>(&payload).unwrap()
            })
        })
        .collect();

    for handle in handles {
        let value = handle.join().unwrap();
        assert!(value.is_object(), "payload: {value}");
    }
}

#[test]
fn workspace_update_publishes_new_snapshot_without_mutating_old_snapshot() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("Thing.java");
    fs::write(&file_path, "public class First {}\n").unwrap();

    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(temp.path()).unwrap());
    let old_snapshot = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("First", true)
            .iter()
            .any(|unit| unit.fq_name() == "First")
    );

    fs::write(&file_path, "public class Second {}\n").unwrap();
    let changed_file = project
        .file_by_rel_path(std::path::Path::new("Thing.java"))
        .unwrap();
    let new_snapshot = old_snapshot.update(&BTreeSet::from([changed_file]));

    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("First", true)
            .iter()
            .any(|unit| unit.fq_name() == "First"),
        "old snapshot should retain First"
    );
    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("Second", true)
            .is_empty(),
        "old snapshot should not see Second"
    );
    assert!(
        new_snapshot
            .analyzer()
            .search_definitions("Second", true)
            .iter()
            .any(|unit| unit.fq_name() == "Second"),
        "new snapshot should see Second"
    );
}

#[test]
fn python_boundary_returns_structured_json() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["summaries"][0]["path"], "A.java");
    assert_eq!(value["summaries"][0]["elements"][0]["start_line"], 3);
}

#[test]
fn service_normalizes_query_code_absolute_where_globs() {
    let root = fixture_root();
    let service = SearchToolsService::new_without_semantic_index(root.clone()).unwrap();
    let arguments = serde_json::json!({
        "match": { "kind": "class", "name": "A" },
        "where": [root.join("A.java").display().to_string()],
        "languages": ["java"]
    });

    let value = service
        .call_tool_value("query_code", arguments)
        .expect("query_code should accept an absolute where path");

    assert_eq!(value["results"][0]["path"], "A.java", "payload: {value}");
    assert_eq!(value["results"][0]["kind"], "class", "payload: {value}");
    assert_eq!(
        value["results"][0]["enclosing_symbol"], "A",
        "payload: {value}"
    );
}

#[test]
fn query_code_loads_workspace_rql_and_json_files() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "class App:\n    pass\n")
        .build();
    let queries = project.root().join("queries");
    fs::create_dir(&queries).expect("query directory");
    let absolute_where = project
        .root()
        .join("app.py")
        .display()
        .to_string()
        .replace('\\', "/");
    fs::write(
        queries.join("app.rql"),
        format!("(where \"{absolute_where}\" (class :name \"App\"))\n"),
    )
    .expect("RQL query");
    fs::write(
        queries.join("app.json"),
        serde_json::json!({
            "where": [absolute_where],
            "match": { "kind": "class", "name": "App" }
        })
        .to_string(),
    )
    .expect("JSON query");
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let rql = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": "queries/app.rql" }),
        )
        .expect("RQL query should run");
    let json = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": "queries/app.json" }),
        )
        .expect("JSON query should run");
    assert_eq!(
        rql, json,
        "equivalent query files should return the same result"
    );

    let inline = service
        .call_tool_value(
            "query_code",
            serde_json::json!({
                "where": [project.root().join("app.py").display().to_string()],
                "match": { "kind": "class", "name": "App" }
            }),
        )
        .expect("inline query should remain supported");
    assert_eq!(rql, inline, "file input must use the existing query engine");
}

#[test]
fn query_code_exposes_planning_only_explain_and_opt_in_profile_reports() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "class App:\n    pass\n")
        .build();
    let queries = project.root().join("queries");
    fs::create_dir(&queries).expect("query directory");
    fs::write(
        queries.join("app-profile.rql"),
        "(profile (class :name \"App\"))\n",
    )
    .expect("profile RQL query");
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let ordinary = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "match": { "kind": "class", "name": "App" } }),
        )
        .expect("ordinary query");
    assert!(ordinary.get("format").is_none(), "{ordinary}");

    let explain = service
        .call_tool_value(
            "query_code",
            serde_json::json!({
                "execution_mode": "explain",
                "match": { "kind": "class", "name": "App" }
            }),
        )
        .expect("explain query");
    assert_eq!(explain["format"], "bifrost_code_query_explain/v1");
    assert_eq!(explain["scheduling"]["selected"], "sequential");
    assert!(explain.get("results").is_none(), "{explain}");

    let profile = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": "queries/app-profile.rql" }),
        )
        .expect("profile query file");
    assert_eq!(profile["format"], "bifrost_code_query_profile/v1");
    assert_eq!(profile["result"], ordinary);
    assert!(
        profile["operators"]
            .as_array()
            .is_some_and(|operators| !operators.is_empty()),
        "{profile}"
    );
    assert_eq!(profile["scheduling"]["peak_concurrency"], 1);
}

#[test]
fn query_code_file_input_reports_validation_and_workspace_errors() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "class App:\n    pass\n")
        .build();
    let queries = project.root().join("queries");
    fs::create_dir(&queries).expect("query directory");
    fs::write(queries.join("broken.rql"), "(class").expect("broken RQL query");
    fs::write(queries.join("broken.json"), "{").expect("broken JSON query");
    fs::write(queries.join("invalid.json"), r#"{"match":{}}"#).expect("invalid JSON query");
    fs::write(queries.join("query.txt"), vec![b'x'; 64 * 1024 + 1]).expect("unsupported query");
    fs::write(queries.join("too-large.rql"), vec![b'x'; 64 * 1024 + 1])
        .expect("oversized RQL query");
    fs::write(queries.join("too-large.json"), vec![b'x'; 64 * 1024 + 1])
        .expect("oversized JSON query");
    fs::create_dir(queries.join("directory.rql")).expect("non-regular query path");
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    for (path, expected) in [
        (
            "queries/missing.rql",
            "failed to read query file `queries/missing.rql`",
        ),
        (
            "queries/broken.rql",
            "failed to parse RQL query file `queries/broken.rql`",
        ),
        (
            "queries/broken.json",
            "failed to parse JSON query file `queries/broken.json`",
        ),
        (
            "queries/invalid.json",
            "invalid CodeQuery in `queries/invalid.json`: invalid query at match",
        ),
        (
            "queries/query.txt",
            "unsupported query file extension `.txt`",
        ),
        (
            "queries/too-large.rql",
            "query file `queries/too-large.rql` is too large",
        ),
        (
            "queries/too-large.json",
            "query file `queries/too-large.json` is too large",
        ),
        (
            "queries/directory.rql",
            "query file `queries/directory.rql` must be a regular file",
        ),
    ] {
        let error = service
            .call_tool_value("query_code", serde_json::json!({ "query_file": path }))
            .expect_err("invalid query file should fail");
        assert_eq!(
            error.code,
            SearchToolsServiceErrorCode::InvalidParams,
            "{error}"
        );
        assert!(error.message.contains(expected), "{error}");
    }

    let mixed = service
        .call_tool_value(
            "query_code",
            serde_json::json!({
                "query_file": "queries/broken.rql",
                "match": { "kind": "class" }
            }),
        )
        .expect_err("mixed query inputs should fail");
    assert!(mixed.message.contains("query_file is exclusive"), "{mixed}");

    let outside = TempDir::new().expect("outside workspace");
    let outside_query = outside.path().join("outside.rql");
    fs::write(&outside_query, "(class :name \"App\")").expect("outside query");
    let outside = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": outside_query.display().to_string() }),
        )
        .expect_err("outside path should fail");
    assert!(
        outside.message.contains("outside active workspace"),
        "{outside}"
    );

    #[cfg(unix)]
    {
        symlink(&outside_query, queries.join("outside-link.rql")).expect("outside symlink");
        let symlink = service
            .call_tool_value(
                "query_code",
                serde_json::json!({ "query_file": "queries/outside-link.rql" }),
            )
            .expect_err("outside symlink should fail");
        assert!(
            symlink.message.contains("outside active workspace"),
            "{symlink}"
        );
    }

    let escaping = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": "../outside.rql" }),
        )
        .expect_err("parent traversal should fail");
    assert!(
        escaping
            .message
            .contains("query file path escapes active workspace"),
        "{escaping}"
    );
}

#[test]
fn rename_symbol_returns_non_mutating_edit_set() {
    let root = fixture_root();
    let before_a = fs::read_to_string(root.join("A.java")).unwrap();
    let service = SearchToolsService::new_without_semantic_index(root.clone()).unwrap();
    let payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":8,"column":19,"new_name":"renamedMethod2"}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("ok", value["status"], "payload: {value}");
    assert_eq!("A.method2", value["target"]["symbol"], "payload: {value}");
    assert_eq!("method2", value["old_name"], "payload: {value}");
    assert!(
        value["edits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "A.java"
                && file["edits"].as_array().unwrap().iter().any(|edit| {
                    edit["new_text"] == "renamedMethod2"
                        && edit["old_text"] == "method2"
                        && edit["start_line"] == 8
                        && edit["start_column"] == 19
                })),
        "payload: {value}"
    );
    assert!(
        value["edits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "B.java"
                && file["edits"].as_array().unwrap().iter().any(|edit| {
                    edit["new_text"] == "renamedMethod2"
                        && edit["start_line"] == 9
                        && edit["start_column"] == 27
                })),
        "payload: {value}"
    );
    assert_eq!(
        before_a,
        fs::read_to_string(root.join("A.java")).unwrap(),
        "rename_symbol must return edits without mutating files"
    );
}

#[test]
fn rename_symbol_selects_generic_csharp_type_source_identifier() {
    let source = r#"namespace Demo;

public class Box<T> {}
public class UseBox { private Box<int> value; }
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Types.cs", source)
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("C# service");
    let declaration_line = "public class Box<T> {}";
    let args = serde_json::json!({
        "path": "Types.cs",
        "line": line_of(source, declaration_line),
        "column": declaration_line.find("Box").unwrap() + 1,
        "new_name": "Container"
    });

    let payload = service
        .call_tool_json("rename_symbol", &args.to_string())
        .expect("rename generic C# type");
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["status"], "ok", "{value}");
    assert_eq!(value["old_name"], "Box", "{value}");
    let edits = value["edits"][0]["edits"].as_array().expect("edits");
    assert_eq!(edits.len(), 2, "{value}");
    assert!(
        edits.iter().all(|edit| edit["old_text"] == "Box"),
        "{value}"
    );
}

#[test]
fn rename_symbol_includes_self_receiver_references() {
    let source = r#"
class Foo {
  target() {}
  caller() {
    this.target();
  }
}
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("service.ts", source)
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");
    let args = serde_json::json!({
        "path": "service.ts",
        "line": 3,
        "column": 3,
        "new_name": "renamed"
    });

    let payload = service
        .call_tool_json("rename_symbol", &args.to_string())
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("ok", value["status"], "payload: {value}");
    let service_edits = value["edits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "service.ts")
        .and_then(|file| file["edits"].as_array())
        .expect("service.ts edits");
    let target_edits: Vec<_> = service_edits
        .iter()
        .filter(|edit| edit["old_text"] == "target" && edit["new_text"] == "renamed")
        .collect();

    assert_eq!(
        2,
        target_edits.len(),
        "rename should edit the declaration and this.target() reference: {value}"
    );
    assert!(
        target_edits.iter().any(|edit| edit["start_line"] == 5),
        "rename must include the self-receiver callsite: {value}"
    );
}

#[test]
fn get_file_contents_reads_workspace_git_history() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("file.py"), "print('v1')\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["file.py"], "v1");
    fs::write(temp.path().join("file.py"), "print('v2')\n").unwrap();
    commit_paths(&repo, &["file.py"], "v2");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let history: Value = serde_json::from_str(
        &service
            .call_tool_json("get_file_contents", r#"{"file_paths":["HEAD~1:file.py"]}"#)
            .unwrap(),
    )
    .unwrap();
    let current: Value = serde_json::from_str(
        &service
            .call_tool_json("get_file_contents", r#"{"file_paths":["file.py"]}"#)
            .unwrap(),
    )
    .unwrap();

    assert_eq!("HEAD~1:file.py", history["files"][0]["path"]);
    assert_eq!("print('v1')\n", history["files"][0]["content"]);
    assert_eq!("print('v2')\n", current["files"][0]["content"]);
}

#[test]
fn scoped_service_reads_selected_files_from_revision() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Demo.java"),
        "class OldDemo {\n  int value() { return 1; }\n}\n",
    )
    .unwrap();
    fs::write(temp.path().join("Other.java"), "class Other {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Demo.java", "Other.java"], "v1");
    fs::write(
        temp.path().join("Demo.java"),
        "class NewDemo {\n  int value() { return 2; }\n}\n",
    )
    .unwrap();
    fs::write(temp.path().join("Other.java"), "class ChangedOther {}\n").unwrap();
    commit_paths(&repo, &["Demo.java", "Other.java"], "v2");

    let service = create_scoped_service(
        temp.path().to_path_buf(),
        &["Demo.java".to_string()],
        Some("HEAD~1"),
    )
    .unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["Demo.java","Other.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let text = value["summaries"][0]["elements"][0]["text"]
        .as_str()
        .unwrap();

    assert!(text.contains("OldDemo"), "payload: {value}");
    assert!(!text.contains("NewDemo"), "payload: {value}");
    assert!(
        value["not_found"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["input"] == "Other.java"),
        "unselected files must not be analyzer-visible: {value}"
    );

    let payload = service
        .call_tool_json("get_file_contents", r#"{"file_paths":["Demo.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value["files"][0]["content"]
            .as_str()
            .unwrap()
            .contains("OldDemo"),
        "file tools must read selected content from the revision: {value}"
    );
    assert!(
        !value["files"][0]["content"]
            .as_str()
            .unwrap()
            .contains("NewDemo"),
        "file tools must not read live content in pinned scoped sessions: {value}"
    );
}

#[test]
fn scoped_service_reads_non_utf8_text_from_revision() {
    let temp = TempDir::new().unwrap();
    // Windows-1252 "é" (0xE9) in a comment: text to git (no NUL bytes) but not
    // valid UTF-8, like the C++/C# sources from brokkbench repos.
    fs::write(
        temp.path().join("Demo.java"),
        b"// caf\xE9\nclass Demo {\n  int value() { return 1; }\n}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Demo.java"], "v1");

    let service = create_scoped_service(
        temp.path().to_path_buf(),
        &["Demo.java".to_string()],
        Some("HEAD"),
    )
    .unwrap();
    let payload = service
        .call_tool_json("get_file_contents", r#"{"file_paths":["Demo.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let content = value["files"][0]["content"].as_str().unwrap();
    assert!(content.contains("class Demo"), "payload: {value}");
    assert!(
        content.contains('\u{FFFD}'),
        "invalid bytes must be replaced lossily: {value}"
    );
}

#[test]
fn scoped_service_resolves_literal_source_paths_at_revision() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src/java/org/jsimpledb")).unwrap();
    fs::write(
        temp.path().join("src/java/org/jsimpledb/Demo.java"),
        "package org.jsimpledb;\nclass Demo { String value() { return \"old\"; } }\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["src/java/org/jsimpledb/Demo.java"], "old layout");

    fs::remove_file(temp.path().join("src/java/org/jsimpledb/Demo.java")).unwrap();
    fs::create_dir_all(temp.path().join("src/main/java/io/permazen")).unwrap();
    fs::write(
        temp.path().join("src/main/java/io/permazen/Demo.java"),
        "package io.permazen;\nclass Demo { String value() { return \"new\"; } }\n",
    )
    .unwrap();
    commit_paths_with_removals(
        &repo,
        &["src/main/java/io/permazen/Demo.java"],
        &["src/java/org/jsimpledb/Demo.java"],
        "new layout",
    );

    let service = create_scoped_service(
        temp.path().to_path_buf(),
        &["src/java/org/jsimpledb/Demo.java".to_string()],
        Some("HEAD~1"),
    )
    .unwrap();
    let payload = service
        .call_tool_json(
            "get_file_contents",
            r#"{"file_paths":["src/java/org/jsimpledb/Demo.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(
        "package org.jsimpledb;\nclass Demo { String value() { return \"old\"; } }\n",
        value["files"][0]["content"],
        "payload: {value}"
    );
    assert!(value["not_found"].as_array().unwrap().is_empty(), "{value}");

    for source in ["src/java/org/jsimpledb", "src/java/org/jsimpledb/*.java"] {
        let service = create_scoped_service(
            temp.path().to_path_buf(),
            &[source.to_string()],
            Some("HEAD~1"),
        )
        .unwrap();
        let payload = service
            .call_tool_json(
                "get_file_contents",
                r#"{"file_paths":["src/java/org/jsimpledb/Demo.java"]}"#,
            )
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(
            "package org.jsimpledb;\nclass Demo { String value() { return \"old\"; } }\n",
            value["files"][0]["content"],
            "revision-scoped source {source} should select old content: {value}"
        );
    }
}

#[test]
fn scoped_service_at_revision_prefers_literal_sources_with_glob_metacharacters() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("a/[x]")).unwrap();
    fs::write(temp.path().join("a/[x]/b.txt"), "literal\n").unwrap();
    fs::write(temp.path().join("a/glob.txt"), "glob\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["a/[x]/b.txt", "a/glob.txt"], "add sources");

    let literal_source = "a/[x]/b.txt";
    let service = create_scoped_service(
        temp.path().to_path_buf(),
        &[literal_source.to_string()],
        Some("HEAD"),
    )
    .unwrap();
    let payload = service
        .call_tool_json(
            "get_file_contents",
            r#"{"file_paths":["a/[x]/b.txt","a/glob.txt"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!("a/[x]/b.txt", value["files"][0]["path"], "payload: {value}");
    assert_eq!(
        "literal\n", value["files"][0]["content"],
        "payload: {value}"
    );
    assert!(
        value["not_found"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str() == Some("a/glob.txt")),
        "literal source must not select unrelated files: {value}"
    );

    let glob_source = "a/g*.txt";
    let service = create_scoped_service(
        temp.path().to_path_buf(),
        &[glob_source.to_string()],
        Some("HEAD"),
    )
    .unwrap();
    let payload = service
        .call_tool_json(
            "get_file_contents",
            r#"{"file_paths":["a/glob.txt","a/[x]/b.txt"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!("a/glob.txt", value["files"][0]["path"], "payload: {value}");
    assert_eq!("glob\n", value["files"][0]["content"], "payload: {value}");
    assert!(
        value["not_found"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str() == Some("a/[x]/b.txt")),
        "glob source should keep normal glob semantics: {value}"
    );
}

#[test]
fn scoped_service_at_revision_reports_working_tree_only_literal_source_path() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Keep.java"), "class Keep {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Keep.java"], "base");

    fs::create_dir_all(temp.path().join("src/main/java/io/permazen")).unwrap();
    fs::write(
        temp.path().join("src/main/java/io/permazen/Demo.java"),
        "package io.permazen;\nclass Demo {}\n",
    )
    .unwrap();
    commit_paths(&repo, &["src/main/java/io/permazen/Demo.java"], "add demo");

    let revision = "HEAD~1";
    let source = "src/main/java/io/permazen/Demo.java";
    let err = match create_scoped_service(
        temp.path().to_path_buf(),
        &[source.to_string()],
        Some(revision),
    ) {
        Ok(_) => panic!("pinned scoped service unexpectedly accepted future source path"),
        Err(err) => err,
    };

    assert!(
        err.contains(source),
        "error must include missing source path: {err}"
    );
    assert!(
        err.contains(revision),
        "error must include pinned revision: {err}"
    );
    assert!(
        err.contains("path exists in the working tree but not at this revision"),
        "error must distinguish working-tree-only paths: {err}"
    );
}

#[test]
fn scoped_service_at_revision_rejects_only_empty_source_paths() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Demo.java"), "class Demo {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Demo.java"], "base");

    let err = match create_scoped_service(
        temp.path().to_path_buf(),
        &["".to_string(), "   ".to_string()],
        Some("HEAD"),
    ) {
        Ok(_) => panic!("pinned scoped service unexpectedly accepted empty source paths"),
        Err(err) => err,
    };

    assert!(
        err.contains(
            "sources resolved to an empty workspace (no non-empty source paths were provided)"
        ),
        "{err}"
    );
}

#[test]
fn scoped_service_at_revision_reports_revision_for_unmatched_glob() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Demo.java"), "class Demo {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Demo.java"], "base");

    let revision = "HEAD";
    let glob = "src/**/*.java";
    let err = match create_scoped_service(
        temp.path().to_path_buf(),
        &[glob.to_string()],
        Some(revision),
    ) {
        Ok(_) => panic!("pinned scoped service unexpectedly accepted unmatched glob"),
        Err(err) => err,
    };

    assert!(err.contains(glob), "error must include source glob: {err}");
    assert!(
        err.contains(revision),
        "error must include pinned revision: {err}"
    );
}

#[test]
fn scoped_service_without_revision_rejects_nonexistent_literal_source_paths() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src/main/java/io/permazen")).unwrap();
    fs::write(
        temp.path().join("src/main/java/io/permazen/Demo.java"),
        "package io.permazen;\nclass Demo {}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(
        &repo,
        &["src/main/java/io/permazen/Demo.java"],
        "current layout",
    );

    let err = match create_scoped_service(
        temp.path().to_path_buf(),
        &["src/java/org/jsimpledb/Demo.java".to_string()],
        None,
    ) {
        Ok(_) => panic!("live scoped service unexpectedly accepted missing source path"),
        Err(err) => err,
    };

    assert!(
        err.contains("source path does not exist: src/java/org/jsimpledb/Demo.java"),
        "{err}"
    );
}

#[test]
fn get_file_contents_reads_cross_repo_absolute_git_history() {
    let repo_a = TempDir::new().unwrap();
    fs::write(repo_a.path().join("workspace.py"), "print('workspace')\n").unwrap();
    let repo_a_git = Repository::init(repo_a.path()).unwrap();
    commit_paths(&repo_a_git, &["workspace.py"], "workspace");

    let repo_b = TempDir::new().unwrap();
    let b_file = repo_b.path().join("client.py");
    fs::write(&b_file, "print('repo b v1')\n").unwrap();
    let repo_b_git = Repository::init(repo_b.path()).unwrap();
    commit_paths(&repo_b_git, &["client.py"], "v1");
    fs::write(&b_file, "print('repo b v2')\n").unwrap();
    commit_paths(&repo_b_git, &["client.py"], "v2");

    let service =
        SearchToolsService::new_without_semantic_index(repo_a.path().to_path_buf()).unwrap();
    let args = serde_json::json!({ "file_paths": [format!("HEAD~1:{}", b_file.display())] });
    let payload = service
        .call_tool_json("get_file_contents", &args.to_string())
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("print('repo b v1')\n", value["files"][0]["content"]);
    assert!(value["not_found"].as_array().unwrap().is_empty(), "{value}");
}

#[test]
fn get_file_contents_reads_deleted_file_from_git_history() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("keep.py"), "print('keep')\n").unwrap();
    fs::write(temp.path().join("deleted.py"), "print('deleted')\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["keep.py", "deleted.py"], "add deleted");
    fs::remove_file(temp.path().join("deleted.py")).unwrap();
    commit_paths_with_removals(&repo, &["keep.py"], &["deleted.py"], "delete");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_file_contents",
            r#"{"file_paths":["HEAD~1:deleted.py"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("print('deleted')\n", value["files"][0]["content"]);
}

#[test]
fn get_file_contents_reports_git_history_errors_in_not_found() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("file.py"), "print('present')\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["file.py"], "present");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_file_contents",
            r#"{"file_paths":["does-not-exist:file.py","HEAD:missing.py"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let errors = value["not_found"].as_array().unwrap();

    assert_eq!(2, errors.len(), "payload: {value}");
    assert!(errors[0].as_str().unwrap().contains("does-not-exist"));
    assert!(errors[0].as_str().unwrap().contains("bad git revision"));
    assert!(errors[1].as_str().unwrap().contains("missing.py"));
    assert!(
        errors[1]
            .as_str()
            .unwrap()
            .contains("absent at git revision `HEAD`")
    );
}

#[test]
#[cfg(not(windows))]
fn get_file_contents_prefers_literal_file_over_rev_syntax() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("x:y.txt"), "literal wins\n").unwrap();
    fs::write(temp.path().join("anchor.py"), "print('anchor')\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["x:y.txt", "anchor.py"], "initial");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json("get_file_contents", r#"{"file_paths":["x:y.txt"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("x:y.txt", value["files"][0]["path"]);
    assert_eq!("literal wins\n", value["files"][0]["content"]);
    assert!(value["not_found"].as_array().unwrap().is_empty(), "{value}");
}

#[test]
fn rename_symbol_rejects_oversized_identifier() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = serde_json::json!({
        "path": "A.java",
        "line": 8,
        "column": 19,
        "new_name": "a".repeat(257)
    });
    let payload = service
        .call_tool_json("rename_symbol", &arguments.to_string())
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("invalid_name", value["status"], "payload: {value}");
    assert!(
        !value["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains(&"a".repeat(257)),
        "payload: {value}"
    );
}

#[test]
fn rename_symbol_requires_line_and_column() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let missing_column_payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":8,"new_name":"renamedMethod2"}"#,
        )
        .unwrap();
    let missing_column: Value = serde_json::from_str(&missing_column_payload).unwrap();
    assert_eq!(
        "invalid_location", missing_column["status"],
        "payload: {missing_column}"
    );

    let missing_line_payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","column":19,"new_name":"renamedMethod2"}"#,
        )
        .unwrap();
    let missing_line: Value = serde_json::from_str(&missing_line_payload).unwrap();
    assert_eq!(
        "invalid_location", missing_line["status"],
        "payload: {missing_line}"
    );
}

#[test]
fn rename_symbol_bad_target_includes_marked_source_context() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":2,"column":1,"new_name":"renamed"}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let message = value["diagnostics"][0]["message"]
        .as_str()
        .expect("rename diagnostic");

    assert_eq!("not_found", value["status"], "payload: {value}");
    assert!(
        message.contains("Requested location: A.java:2:1"),
        "{message}"
    );
    assert!(
        message.contains("1 | import java.util.function.Function;"),
        "{message}"
    );
    assert!(message.contains(">  2 |"), "{message}");
    assert!(message.contains("3 | public class A"), "{message}");
    assert!(
        message.contains("^ requested line 2, column 1"),
        "{message}"
    );
    assert!(message.contains("Recovery:"), "{message}");
    assert!(message.contains("identifier token"), "{message}");
}

#[test]
fn rename_symbol_rejects_file_coupled_java_class() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":3,"column":14,"new_name":"RenamedA"}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("unsupported", value["status"], "payload: {value}");
    assert!(
        value["edits"].as_array().unwrap().is_empty(),
        "payload: {value}"
    );
    assert_eq!(
        "unsupported", value["diagnostics"][0]["kind"],
        "payload: {value}"
    );
}

#[test]
fn rename_symbol_rejects_invalid_identifier() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "rename_symbol",
            r#"{"path":"A.java","line":8,"column":19,"new_name":"not-valid"}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!("invalid_name", value["status"], "payload: {value}");
    assert!(
        value["edits"].as_array().unwrap().is_empty(),
        "payload: {value}"
    );
}

#[test]
fn get_summaries_directory_target_stays_narrow_on_service_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["."]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["structured"]["summaries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        value["structured"]["not_found"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!("directory", value["structured"]["listings"][0]["kind"]);
    assert_eq!(".", value["structured"]["listings"][0]["target"]);
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("Directory ."), "{rendered}");
    assert!(rendered.contains("A.java"), "{rendered}");
}

#[test]
fn get_summaries_mixed_targets_stay_narrow_on_service_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["A.java","."]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["structured"]["summaries"][0]["path"], "A.java");
    assert!(
        value["structured"]["not_found"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!("directory", value["structured"]["listings"][0]["kind"]);
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("A.java"), "{rendered}");
    assert!(rendered.contains("Directory ."), "{rendered}");
}

#[test]
fn get_summaries_large_file_glob_stays_full_fidelity_on_service_path() {
    let temp = TempDir::new().unwrap();
    for class_idx in 0..18 {
        let mut source = format!("public class Caller{class_idx} {{\n");
        for method_idx in 0..12 {
            source.push_str(&format!(
                "    public int method{method_idx}(int input) {{ return input + {class_idx} + {method_idx}; }}\n"
            ));
        }
        source.push_str("}\n");
        fs::write(temp.path().join(format!("Caller{class_idx}.java")), source).unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["*.java"]}"#)
        .unwrap();

    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value.get("degraded").is_none() || value["degraded"].is_null(),
        "{value}"
    );
    assert!(
        value.get("degradation").is_none() || value["degradation"].is_null(),
        "{value}"
    );
    assert_eq!(18, value["summaries"].as_array().unwrap().len(), "{value}");
    assert!(
        value["compact_symbols"].is_null(),
        "service path should not degrade to compact_symbols: {value}"
    );
}

#[test]
fn get_definitions_by_reference_resolves_rust_crate_scoped_item() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("lib.rs"),
        r#"pub fn helper() {}

pub fn caller() {
    crate::helper();
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"caller","context":"    crate::helper();","target":"helper"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!("helper", result["definitions"][0]["fqn"], "{value}");
}

#[test]
fn get_definitions_by_reference_accepts_js_file_anchored_symbols() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/core.ts",
            "function helper() { return 1; }\nexport class ProcessPromise { pipe() { return helper(); } }\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    for symbol in [
        "src/core.ts#ProcessPromise.pipe",
        "src/core.ts.ProcessPromise.pipe",
    ] {
        let payload = service
            .call_tool_json(
                "get_definitions_by_reference",
                &serde_json::json!({
                    "references": [{
                        "symbol": symbol,
                        "context": "pipe() { return helper(); }",
                        "target": "helper"
                    }]
                })
                .to_string(),
            )
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let result = &value["results"][0];
        assert_eq!("resolved", result["status"], "{value}");
        assert_eq!("helper", result["definitions"][0]["fqn"], "{value}");
    }
}

// #1057 M3: the `definitions` (reference) surface must report ambiguity in the
// same conditions as get_symbol_sources/get_summaries. A bare terminal name
// whose only exact hit is a top-level namesake, while a same-named member
// exists, previously short-circuited on resolve_codeunit_exact and silently
// resolved the free function. It must now report status "not_found" with an
// `ambiguous_symbol` diagnostic listing both file-anchored selectors — the same
// selectors the sources surface offers (the fuzzer's cross-surface
// spelling-status-drift shape). The fully-qualified member spelling still
// resolves (unique qualified name → Ok).
#[test]
fn get_definitions_by_reference_reports_member_collision_ambiguity() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "checker/cached-version.ts",
            "export function getCachedVersion() {\n  return 1;\n}\n",
        )
        .file(
            "hook.ts",
            "export function seed() {\n  return 0;\n}\nexport class AutoUpdateCheckerDeps {\n  getCachedVersion() {\n    return seed();\n  }\n}\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    // Bare name is ambiguous on the reference surface (previously a silent pick).
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            &serde_json::json!({
                "references": [{
                    "symbol": "getCachedVersion",
                    "context": "return 1;",
                    "target": "return"
                }]
            })
            .to_string(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let result = &value["results"][0];
    assert_eq!("not_found", result["status"], "{value}");
    assert_eq!(
        "ambiguous_symbol", result["diagnostics"][0]["kind"],
        "{value}"
    );
    let message = result["diagnostics"][0]["message"].as_str().unwrap();
    assert!(message.contains("is ambiguous; matches:"), "{value}");

    // Cross-surface consistency: get_symbol_sources offers the SAME selectors,
    // and the reference-surface diagnostic lists exactly those selectors.
    let sources_payload = service
        .call_tool_json("get_symbol_sources", r#"{"symbols":["getCachedVersion"]}"#)
        .unwrap();
    let sources: Value = serde_json::from_str(&sources_payload).unwrap();
    let source_matches: Vec<String> = sources["ambiguous"][0]["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().to_string())
        .collect();
    assert_eq!(2, source_matches.len(), "{sources}");
    for selector in &source_matches {
        assert!(
            message.contains(selector),
            "reference surface must list {selector}: {value}"
        );
    }

    // The fully-qualified member spelling still resolves (unique → Ok).
    let qualified_payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            &serde_json::json!({
                "references": [{
                    "symbol": "AutoUpdateCheckerDeps.getCachedVersion",
                    "context": "return seed();",
                    "target": "seed"
                }]
            })
            .to_string(),
        )
        .unwrap();
    let qualified: Value = serde_json::from_str(&qualified_payload).unwrap();
    assert_eq!("resolved", qualified["results"][0]["status"], "{qualified}");
    assert_eq!(
        "seed", qualified["results"][0]["definitions"][0]["fqn"],
        "{qualified}"
    );
}

// #1057 M3: identical-FQN twins (same fq in two files) must report ambiguity on
// the reference surface for BOTH the bare and the fully-qualified spelling, with
// the same file-anchored selectors — before M3 the fully-qualified spelling
// short-circuited on resolve_codeunit_exact and silently returned both twins
// with no ambiguity signal.
#[test]
fn get_definitions_by_reference_reports_twin_fqn_ambiguity() {
    let scala2_path = "core/src/main/scala-2/demo/Widget.scala";
    let scala3_path = "core/src/main/scala-3/demo/Widget.scala";
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            scala2_path,
            "package demo\n\nclass Widget {\n  def value: Int = 2\n}\n",
        )
        .file(
            scala3_path,
            "package demo\n\nclass Widget {\n  def value: Int = 3\n}\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let expected = vec![
        format!("{scala2_path}#demo.Widget"),
        format!("{scala3_path}#demo.Widget"),
    ];

    for symbol in ["demo.Widget", "Widget"] {
        let payload = service
            .call_tool_json(
                "get_definitions_by_reference",
                &serde_json::json!({
                    "references": [{
                        "symbol": symbol,
                        "context": "def value",
                        "target": "value"
                    }]
                })
                .to_string(),
            )
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let result = &value["results"][0];
        assert_eq!("not_found", result["status"], "{symbol}: {value}");
        assert_eq!(
            "ambiguous_symbol", result["diagnostics"][0]["kind"],
            "{symbol}: {value}"
        );
        let message = result["diagnostics"][0]["message"].as_str().unwrap();
        for selector in &expected {
            assert!(
                message.contains(selector.as_str()),
                "{symbol} must list {selector}: {value}"
            );
        }
    }
}

#[test]
fn get_definitions_guidance_matches_call_surface_for_qualified_targets() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let source = r#"pub fn helper() {}

pub fn caller() {
    crate::helper();
}
"#;
    fs::write(src.join("lib.rs"), source).unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let by_reference_payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"caller","context":"    crate::helper();","target":"crate::helper"}]}"#,
        )
        .unwrap();
    let by_reference: Value = serde_json::from_str(&by_reference_payload).unwrap();
    let reference_message = by_reference["results"][0]["diagnostics"][0]["message"]
        .as_str()
        .expect("by-reference diagnostic message");

    assert_eq!(
        "invalid_location", by_reference["results"][0]["status"],
        "{by_reference}"
    );
    assert!(reference_message.contains("target must identify a single reference token"));
    assert!(!reference_message.contains("start_byte"));

    let by_location_payload = service
        .call_tool_json(
            "get_definitions_by_location",
            r#"{"references":[{"path":"src/lib.rs","line":4,"column":12}]}"#,
        )
        .unwrap();
    let by_location: Value = serde_json::from_str(&by_location_payload).unwrap();
    assert_eq!(
        "resolved", by_location["results"][0]["status"],
        "{by_location}"
    );
    assert_eq!("helper", by_location["results"][0]["definitions"][0]["fqn"]);
}

#[test]
fn get_definitions_by_reference_reports_path_symbol_guidance() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("lib.rs"),
        r#"pub fn helper() {}

pub fn caller() {
    helper();
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"src/lib.rs","context":"    helper();","target":"helper"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let result = &value["results"][0];
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");

    assert_eq!("not_found", result["status"], "{value}");
    assert_eq!(
        "symbol_not_found", result["diagnostics"][0]["kind"],
        "{value}"
    );
    assert!(
        message.contains("`symbol` must be an enclosing workspace symbol, not a file path"),
        "{message}"
    );
    assert!(
        message.contains("`context` must be exact source text"),
        "{message}"
    );
    assert!(message.contains("get_summaries"), "{message}");
    assert!(message.contains("get_symbol_sources"), "{message}");
}

#[test]
fn get_definitions_by_reference_resolves_go_method_receiver_field_chain() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("main.go"),
        r#"package app

type Helper struct{}

func (h Helper) UpdatePackageMetadata() error { return nil }

type Client struct { npmMetadataHelper Helper }

func (c *Client) Build() error {
    return c.npmMetadataHelper.UpdatePackageMetadata()
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"example.com/app.Client.Build","context":"    return c.npmMetadataHelper.UpdatePackageMetadata()","target":"UpdatePackageMetadata"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "example.com/app.Helper.UpdatePackageMetadata", result["definitions"][0]["fqn"],
        "{value}"
    );
}

#[test]
fn get_definitions_by_reference_matches_exact_identifier_target() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "freqtrade/exchange/exchange_utils.py",
            r#"EXCHANGE_HAS_OPTIONAL = "spot"
EXCHANGE_HAS_OPTIONAL_FUTURES = "futures"

def _exchange_has_helper(ex_has, key):
    return key in ex_has

def validate_exchange(ex_has):
    _exchange_has_helper(ex_has, EXCHANGE_HAS_OPTIONAL)
    _exchange_has_helper(ex_has, EXCHANGE_HAS_OPTIONAL_FUTURES)
"#,
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let args = serde_json::json!({
        "references": [{
            "symbol": "exchange_utils.validate_exchange",
            "context": "    _exchange_has_helper(ex_has, EXCHANGE_HAS_OPTIONAL)\n    _exchange_has_helper(ex_has, EXCHANGE_HAS_OPTIONAL_FUTURES)",
            "target": "EXCHANGE_HAS_OPTIONAL"
        }]
    })
    .to_string();
    let payload = service
        .call_tool_json("get_definitions_by_reference", &args)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        1,
        result["definitions"].as_array().unwrap().len(),
        "{value}"
    );
    assert_eq!(
        "freqtrade.exchange.exchange_utils.EXCHANGE_HAS_OPTIONAL", result["definitions"][0]["fqn"],
        "{value}"
    );
}

#[test]
fn get_definitions_by_reference_resolves_cpp_overload_by_argument_type() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("target.h"),
        r#"namespace ncnn {
class DataReader {};
class DataReaderFromMemory : public DataReader {};
class Net {
public:
    int load_model(const char* path);
    int load_model(const DataReader& dr);
};
}
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("app.cpp"),
        r#"#include "target.h"
using namespace ncnn;

class DataReaderFromMemoryCopy : public DataReaderFromMemory {};

void PYBIND11_MODULE(Net& net, DataReaderFromMemoryCopy& dr) {
    net.load_model(dr);
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"PYBIND11_MODULE","context":"    net.load_model(dr);","target":"load_model"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "ncnn.Net.load_model", result["definitions"][0]["fqn"],
        "{value}"
    );
    assert_eq!(
        "(const DataReader &)", result["definitions"][0]["signature"],
        "{value}"
    );
}

#[test]
fn get_definitions_by_reference_resolves_cpp_constructor_style_local_argument() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("target.h"),
        r#"namespace ncnn {
class DataReader {};
class DataReaderFromMemory : public DataReader {};
class Net {
public:
    int load_model(const char* path);
    int load_model(const DataReader& dr);
};
}
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("app.cpp"),
        r#"#include "target.h"
using namespace ncnn;

class DataReaderFromMemoryCopy : public DataReaderFromMemory {
public:
    explicit DataReaderFromMemoryCopy(const unsigned char*& mem);
};

void PYBIND11_MODULE(Net& net, const char* mem) {
    const unsigned char* _mem = (const unsigned char*)mem;
    DataReaderFromMemoryCopy dr(_mem);
    net.load_model(dr);
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"PYBIND11_MODULE","context":"    net.load_model(dr);","target":"load_model"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "ncnn.Net.load_model", result["definitions"][0]["fqn"],
        "{value}"
    );
    assert_eq!(
        "(const DataReader &)", result["definitions"][0]["signature"],
        "{value}"
    );
}

#[test]
fn get_definitions_by_reference_resolves_scala_constructor_field_from_symbol_context() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("app")).unwrap();
    fs::write(
        temp.path().join("app").join("StreamContext.scala"),
        r#"package com.netflix.atlas.eval.stream
class Registry
class FlowShape
class GraphStage[T]

private[stream] class StreamContext(
  rootConfig: String,
  val registry: Registry
)
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("app").join("TimeGrouped.scala"),
        r#"package com.netflix.atlas.eval.stream

object AggrDatapoint {
  def AggregatorSettings(input: Int, intermediate: Int, registry: Registry, host: String): Int = 0
}

private[stream] class TimeGrouped(
  context: StreamContext,
  host: String
) extends GraphStage[FlowShape] {
  private val maxInputDatapointsPerExpression = 1
  private val maxIntermediateDatapointsPerExpression = 2
  private val aggrSettings = AggrDatapoint.AggregatorSettings(
    maxInputDatapointsPerExpression,
    maxIntermediateDatapointsPerExpression,
    context.registry,
    host
  )
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"com.netflix.atlas.eval.stream.TimeGrouped","context":"    context.registry,","target":"registry"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("resolved", result["status"], "{value}");
    assert_eq!(
        "com.netflix.atlas.eval.stream.StreamContext.registry", result["definitions"][0]["fqn"],
        "{value}"
    );
}

#[test]
fn get_definitions_by_reference_reports_scala_receiver_guidance() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Consumer.scala",
            r#"package app
class Consumer {
  def run(service: UnknownService): Unit = {
    service.changeOrganisation()
  }
}
"#,
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"app.Consumer","context":"    service.changeOrganisation()","target":"changeOrganisation"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("no_definition", result["status"], "{value}");
    assert_eq!(
        "unsupported_scala_receiver", result["diagnostics"][0]["kind"],
        "{value}"
    );
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(
        message.contains("reference tool cannot follow this Scala receiver/member shape yet"),
        "{message}"
    );
    assert!(message.contains("search_symbols"), "{message}");
    assert!(message.contains("changeOrganisation"), "{message}");
    assert!(message.contains("get_symbol_sources"), "{message}");
    assert!(!message.contains("start_byte"), "{message}");
}

#[test]
fn get_definitions_by_reference_redirects_scala_parameter_to_location_lookup() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Consumer.scala",
            r#"package app
class Consumer {
  def run(factory: () => () => Int): Int = {
    factory()()
  }
}
"#,
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"app.Consumer","context":"    factory()()","target":"factory"}]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let result = &value["results"][0];
    assert_eq!("no_definition", result["status"], "{value}");
    assert_eq!(
        "local_binding_requires_location", result["diagnostics"][0]["kind"],
        "{value}"
    );
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(message.contains("get_definitions_by_location"), "{message}");
    assert!(message.contains("lexical binding"), "{message}");
}

#[test]
fn python_boundary_returns_canonical_rendered_text_payload() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["A.method2"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["structured"]["sources"][0]["start_line"], 8);
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("## A.method2"), "{rendered}");
    assert!(rendered.contains("- Location: A.java:8..10"), "{rendered}");
    assert!(
        rendered.contains("8: public String method2(String input)"),
        "{rendered}"
    );
}

#[test]
fn get_symbol_sources_file_input_returns_top_level_outline_payload() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/pkg/Thing.java",
            r#"package pkg;
class Thing {
    void method() {}
    static class Inner {}
}
"#,
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["src/pkg/Thing.java"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let source = &value["structured"]["sources"][0];
    assert_eq!("src/pkg/Thing.java", source["label"]);
    assert_eq!("src/pkg/Thing.java", source["path"]);
    assert_eq!(1, source["start_line"]);
    assert_eq!(2, source["end_line"]);
    let source_text = source["text"].as_str().expect("source text");
    assert!(source_text.contains("# pkg"), "{source_text}");
    assert!(source_text.contains("- Thing"), "{source_text}");
    assert!(!source_text.contains("method"), "{source_text}");
    assert!(!source_text.contains("Inner"), "{source_text}");
    assert_eq!(
        "file target: showing a flat outline of top-level symbols, not the full source; pass a symbol name for its full body, or use get_summaries for structured summaries",
        source["note"]
    );

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("## src/pkg/Thing.java"), "{rendered}");
    assert!(
        rendered.contains(
            "- Note: file target: showing a flat outline of top-level symbols, not the full source"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("- Location: src/pkg/Thing.java:1..2"),
        "{rendered}"
    );
    assert!(
        rendered.contains("```text\n1: # pkg\n2: - Thing\n```"),
        "{rendered}"
    );
}

#[test]
fn get_symbol_sources_js_file_input_keeps_module_scoped_selector_copy() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/plugin/relativeTime/index.js",
            "export default function relativeTime() {\n  return 'now';\n}\n",
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["src/plugin/relativeTime/index.js"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let note = value["structured"]["sources"][0]["note"]
        .as_str()
        .expect("source note");
    assert!(
        note.contains("src/plugin/relativeTime/index.js#default"),
        "{note}"
    );
    assert!(note.contains("JS/TS module-scoped symbols"), "{note}");

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("src/plugin/relativeTime/index.js#default"),
        "{rendered}"
    );
}

#[test]
fn get_symbol_sources_file_input_uses_include_and_sample_fallbacks() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("only_includes.h"),
        "#pragma once\n#include \"only/include.h\"\n#include <stdint.h>\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src").join("emptyish_large.h"),
        (1..=60)
            .map(|line| format!("// line {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["src/only_includes.h","src/emptyish_large.h"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let sources = value["structured"]["sources"].as_array().unwrap();
    let include_source = sources
        .iter()
        .find(|source| source["path"] == "src/only_includes.h")
        .unwrap();
    assert_eq!(2, include_source["start_line"]);
    assert_eq!(3, include_source["end_line"]);
    assert_eq!(
        "#include \"only/include.h\"\n#include <stdint.h>",
        include_source["text"]
    );
    assert_eq!(
        "no indexed declarations found in this file; showing its top-level #include lines, not the full source",
        include_source["note"]
    );

    let sampled_source = sources
        .iter()
        .find(|source| source["path"] == "src/emptyish_large.h")
        .unwrap();
    assert_eq!(1, sampled_source["start_line"]);
    assert_eq!(60, sampled_source["end_line"]);
    assert_eq!("sampled_excerpt", sampled_source["presentation"]);
    assert_eq!(
        "no indexed declarations or top-level includes found in this file; showing a head/tail sample with the first 25 and last 25 of its 60 lines (the middle is omitted)",
        sampled_source["note"]
    );
    let sampled_text = sampled_source["text"].as_str().expect("sampled text");
    assert!(sampled_text.contains("// line 1"), "{sampled_text}");
    assert!(
        sampled_text.contains("----- OMITTED 10 LINES -----"),
        "{sampled_text}"
    );
    assert!(sampled_text.contains("// line 60"), "{sampled_text}");

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("- Location: src/only_includes.h:2..3"),
        "{rendered}"
    );
    assert!(
        rendered.contains("#include \"only/include.h\""),
        "{rendered}"
    );
    assert!(
        rendered.contains("- Location: src/emptyish_large.h:1..60"),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "- Note: no indexed declarations or top-level includes found in this file; showing a head/tail sample with the first 25 and last 25 of its 60 lines (the middle is omitted)"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "- Note: no indexed declarations found in this file; showing its top-level #include lines, not the full source"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("----- OMITTED 10 LINES -----"),
        "{rendered}"
    );
    // The sampled excerpt body must not be line-numbered: sequential numbering
    // across the omitted gap would fabricate line numbers for the tail half.
    assert!(!rendered.contains(": ----- OMITTED"), "{rendered}");
    assert!(rendered.contains("// line 60"), "{rendered}");
    assert!(!rendered.contains(": // line 60"), "{rendered}");
}

#[test]
fn legacy_kind_filter_is_ignored_for_symbol_sources_and_locations() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    let source_payload = service
        .call_tool_json(
            "get_symbol_sources",
            r#"{"symbols":["A.method2"],"kind_filter":"function"}"#,
        )
        .unwrap();
    let source_value: Value = serde_json::from_str(&source_payload).unwrap();
    assert_eq!("A.method2", source_value["sources"][0]["label"]);

    let location_payload = service
        .call_tool_json(
            "get_symbol_locations",
            r#"{"symbols":["A.method2"],"kind_filter":"function"}"#,
        )
        .unwrap();
    let location_value: Value = serde_json::from_str(&location_payload).unwrap();
    assert_eq!("A.method2", location_value["locations"][0]["symbol"]);
}

#[test]
fn get_symbol_ancestors_reports_non_type_targets_as_not_found() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Thing.java"),
        "class Base {}\nclass Thing extends Base { void run() {} }\n",
    )
    .unwrap();
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json("get_symbol_ancestors", r#"{"symbols":["Thing.run"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, value["ancestors"].as_array().unwrap().len(), "{value}");
    assert_eq!(1, value["not_found"].as_array().unwrap().len(), "{value}");
    assert_eq!("Thing.run", value["not_found"][0]["input"], "{value}");
    assert_eq!(
        "resolves to a function; get_symbol_ancestors only accepts class/module/type symbols",
        value["not_found"][0]["note"],
        "{value}"
    );
}

#[test]
fn get_summaries_renders_include_and_excerpt_fallbacks() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("only_includes.h"),
        "#pragma once\n#include \"only/include.h\"\n#include <stdint.h>\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src").join("emptyish.h"),
        (1..=25)
            .map(|line| format!("// line {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["src/only_includes.h","src/emptyish.h"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let summaries = value["structured"]["summaries"].as_array().unwrap();
    let include_summary = summaries
        .iter()
        .find(|summary| summary["path"] == "src/only_includes.h")
        .unwrap();
    assert_eq!(
        "no indexed declarations found; showing top-level includes",
        include_summary["fallback_reason"]
    );
    assert_eq!("include", include_summary["elements"][0]["kind"]);
    assert_eq!("only/include.h", include_summary["elements"][0]["symbol"]);

    let excerpt_summary = summaries
        .iter()
        .find(|summary| summary["path"] == "src/emptyish.h")
        .unwrap();
    assert_eq!(
        "no indexed declarations or top-level includes found in this file; showing its full text (25 lines)",
        excerpt_summary["fallback_reason"]
    );
    assert_eq!("excerpt", excerpt_summary["elements"][0]["kind"]);
    assert_eq!(25, excerpt_summary["elements"][0]["end_line"]);
    assert_eq!(
        "sampled_excerpt",
        excerpt_summary["elements"][0]["presentation"]
    );

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("Note: no indexed declarations found; showing top-level includes"),
        "{rendered}"
    );
    assert!(
        rendered.contains("#include \"only/include.h\""),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "Note: no indexed declarations or top-level includes found in this file; showing its full text (25 lines)"
        ),
        "{rendered}"
    );
    assert!(rendered.contains("// line 1"), "{rendered}");
}

#[test]
fn python_boundary_returns_structural_clone_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Alpha.java"),
        "class Alpha { int compute(int input) { int total = input + 1; if (total > 10) { return total * 2; } return total - 3; } }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Beta.java"),
        "class Beta { int calculate(int seed) { int amount = seed + 1; if (amount > 10) { return amount * 2; } return amount - 3; } }\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_structural_clone_smells",
            r#"{"file_paths":["Alpha.java","Beta.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["report"]
            .as_str()
            .expect("report string")
            .starts_with("## Structural clone smells"),
        "payload: {value}"
    );
}

#[test]
fn python_boundary_returns_dead_code_smell_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("helpers.rs"), "fn helper() {}\n").unwrap();
    fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_dead_code_and_unused_abstraction_smells",
            r#"{"file_paths":["helpers.rs","main.rs"],"fq_names":["helpers.helper"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let report = value["report"].as_str().expect("report string");
    assert!(
        report.starts_with("## Dead code and unused abstraction smells"),
        "payload: {value}"
    );
    assert!(report.contains("helpers.helper"), "payload: {value}");
}

#[test]
fn python_boundary_returns_secret_scan_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.properties"),
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_path(std::path::Path::new("config.properties"))
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    repo.reference_symbolic(
        "refs/remotes/origin/HEAD",
        "refs/heads/master",
        true,
        "set remote default",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_secret_like_code",
            r#"{"max_findings":10,"max_commits":10}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["report"]
            .as_str()
            .expect("report string")
            .starts_with("## brokk-secret-scan"),
        "payload: {value}"
    );
    assert!(
        !value["report"]
            .as_str()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE"),
        "payload: {value}"
    );
}

#[test]
fn python_boundary_returns_git_hotspot_report_json() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("ComplexService.java"),
        "public class ComplexService { void hotspot(int x) { if (x > 0) {} if (x > 1) {} if (x > 2) {} if (x > 3) {} if (x > 4) {} if (x > 5) {} if (x > 6) {} if (x > 7) {} if (x > 8) {} if (x > 9) {} if (x > 10) {} if (x > 11) {} if (x > 12) {} if (x > 13) {} if (x > 14) {} } }\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["src/ComplexService.java"], "initial");
    for i in 0..11 {
        fs::write(
            temp.path().join("src").join("ComplexService.java"),
            format!("public class ComplexService {{ void hotspot(int x) {{ int marker = {i}; if (x > 0) {{}} if (x > 1) {{}} if (x > 2) {{}} if (x > 3) {{}} if (x > 4) {{}} if (x > 5) {{}} if (x > 6) {{}} if (x > 7) {{}} if (x > 8) {{}} if (x > 9) {{}} if (x > 10) {{}} if (x > 11) {{}} if (x > 12) {{}} if (x > 13) {{}} if (x > 14) {{}} }} }}\n"),
        )
        .unwrap();
        commit_paths(&repo, &["src/ComplexService.java"], &format!("update {i}"));
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "analyze_git_hotspots",
            r#"{"since_iso":"2020-01-01T00:00:00Z","max_commits":500,"max_files":75}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let report = value["report"].as_str().expect("report string");
    assert_eq!(
        report,
        format!(
            "## Git hotspots\n\n- Repository: `{}`\n- Timeframe: since 2020-01-01T00:00:00Z\n- Analyzed commits: 12\n- Unique files (before cap): 1\n- Truncated: false\n\n| Path | Churn | Complexity | Category | Authors |\n|------|-------|------------|----------|---------|\n| `src{sep}ComplexService.java` | 12 | 16 | HOTSPOT | Test User(12) |",
            temp.path().canonicalize().unwrap().display(),
            sep = MAIN_SEPARATOR
        )
    );
}

#[test]
fn python_boundary_returns_list_symbols_json() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("list_symbols", r#"{"file_patterns":["A.java"]}"#)
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
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
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

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "most_relevant_files",
            r#"{"seed_file_paths":["A.java"],"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["files"].as_array().unwrap();
    assert!(
        files.iter().any(|item| item == "B.java"),
        "payload: {value}"
    );
    assert_eq!(0, value["not_found"].as_array().unwrap().len());

    let usage_payload = service
        .call_tool_json(
            "most_relevant_files",
            r#"{"seed_file_paths":["A.java"],"ranking_mode":"usage_graph","limit":5}"#,
        )
        .unwrap();
    let usage_value: Value = serde_json::from_str(&usage_payload).unwrap();
    assert_eq!(value["files"], usage_value["files"]);
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

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":[".*"],"include_tests":true,"limit":1}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["truncated"]);
    assert_eq!(
        "Showing 1 of 2 matching files. Raise `limit` or use a more specific identifier, qualified, or regex-like pattern to see the rest.",
        value["note"],
        "payload: {value}"
    );
    let files = value["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("z_high.java", files[0]["path"]);
    assert_eq!("class ZHigh", files[0]["classes"][0]["signature"]);
    assert_eq!(1, files[0]["classes"][0]["line"]);

    let payload = service
        .call_tool_payload_json(
            "search_symbols",
            r#"{"patterns":[".*"],"include_tests":true,"limit":1}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("- Note: Showing 1 of 2 matching files. Raise `limit` or use a more specific identifier, qualified, or regex-like pattern to see the rest."),
        "{rendered}"
    );
}

#[test]
fn list_symbols_truncation_reports_recovery_note() {
    let temp = TempDir::new().unwrap();
    for index in 0..21 {
        fs::write(
            temp.path().join(format!("Generated{index}.java")),
            format!("class Generated{index} {{}}\n"),
        )
        .unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "list_symbols",
            r#"{"file_patterns":["*.java"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["structured"]["truncated"], "payload: {value}");
    assert_eq!(20, value["structured"]["files"].as_array().unwrap().len());
    assert_eq!(
        "Showing 20 of 21 selected files. Narrow `file_patterns` on list_symbols or `targets` on get_summaries to see the rest.",
        value["structured"]["note"],
        "payload: {value}"
    );
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("Note: Showing 20 of 21 selected files. Narrow `file_patterns` on list_symbols or `targets` on get_summaries to see the rest."),
        "{rendered}"
    );
}

#[test]
fn search_symbols_prefers_exact_match_over_hot_partial_match_file() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("BootmgrApple.java"),
        "class BootmgrApple { void ffDetectBootmgr() {} }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("BootmgrUtility.java"),
        "class BootmgrUtility {\n    void ffDetectBootmgrFallback() {}\n}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["BootmgrApple.java"], "add exact match");
    commit_paths(&repo, &["BootmgrUtility.java"], "add utility");
    fs::write(
        temp.path().join("BootmgrUtility.java"),
        "class BootmgrUtility {\n    void ffDetectBootmgrFallback() {}\n    void ffDetectBootmgrTelemetry() {}\n}\n",
    )
    .unwrap();
    commit_paths(&repo, &["BootmgrUtility.java"], "heat utility");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["ffDetectBootmgr"],"include_tests":true,"limit":1}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["truncated"]);
    let files = value["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("BootmgrApple.java", files[0]["path"], "payload: {value}");
    assert_eq!(
        "void ffDetectBootmgr()",
        files[0]["functions"][0]["signature"]
    );
}

#[test]
fn get_active_workspace_returns_initial_root() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_workspace_path(&value, &fixture_root());
}

#[test]
fn activate_workspace_rejects_relative_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
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
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
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

    let service = SearchToolsService::new_without_semantic_index(same_root.clone()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&same_root.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_workspace_path(&value, &same_root);
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

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&new_root.display().to_string()).unwrap()
    );
    let activate_payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let activate_value: Value = serde_json::from_str(&activate_payload).unwrap();
    assert_workspace_path(&activate_value, &new_root);

    let get_payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let get_value: Value = serde_json::from_str(&get_payload).unwrap();
    assert_workspace_path(&get_value, &new_root);

    // The new workspace should index files from the new root, not the old one.
    let summary_payload = service
        .call_tool_json("list_symbols", r#"{"file_patterns":["Switched.java"]}"#)
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

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

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
    assert_workspace_path(&active_value, &fixture_root());

    let summary_payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let summary_value: Value = serde_json::from_str(&summary_payload).unwrap();
    assert_eq!(summary_value["summaries"][0]["path"], "A.java");
}

#[test]
fn scan_usages_returns_call_sites_grouped_by_file() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["E.iMethod"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let usage = only_result(&value);
    assert_eq!("E.iMethod", usage["symbol"]);
    assert_eq!("found", usage["status"]);
    assert!(
        usage["total_hits"].as_u64().unwrap() >= 1,
        "expected >=1 hit, payload: {value}"
    );
    assert!(
        usage["complete"].is_null(),
        "complete should be omitted when true: {value}"
    );

    let files = usage["files"].as_array().unwrap();
    let use_e = files
        .iter()
        .find(|file| file["path"] == "UseE.java")
        .unwrap_or_else(|| panic!("expected UseE.java in files: {value}"));
    let hits = use_e["hits"].as_array().unwrap();
    assert!(
        hits.iter().any(|hit| hit["snippet"]
            .as_str()
            .unwrap_or_default()
            .contains("e.iMethod()")),
        "expected snippet to contain `e.iMethod()`: {value}"
    );

    assert_eq!(0, status_count(&value, "not_found"));
    assert_eq!(0, status_count(&value, "ambiguous"));
    assert_eq!(0, status_count(&value, "failure"));
    assert_eq!(0, status_count(&value, "too_many_callsites"));
}

#[test]
fn scan_usages_full_rows_preserve_distinct_same_line_unicode_ranges() {
    let source = "export function target() {}\nexport function caller() { const café = 1; target(); target(); }\n";
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", source)
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_payload_json(
            "scan_usages_by_reference",
            r#"{"symbols":["app.js#target"],"include_tests":true}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value["structured"]);

    assert_eq!("full", usage["rendering"], "payload: {value}");
    assert_eq!(2, usage["total_hits"], "payload: {value}");
    let hits = usage["files"][0]["hits"].as_array().unwrap();
    assert_eq!(2, hits.len(), "payload: {value}");

    let call_line = source.lines().nth(1).unwrap();
    let expected_columns = call_line
        .match_indices("target")
        .map(|(byte, token)| {
            let start = call_line[..byte].chars().count() + 1;
            (start, start + token.chars().count())
        })
        .collect::<Vec<_>>();
    let actual_ranges = hits
        .iter()
        .map(|hit| {
            (
                hit["line"].as_u64().unwrap() as usize,
                hit["column"].as_u64().unwrap() as usize,
                hit["end_line"].as_u64().unwrap() as usize,
                hit["end_column"].as_u64().unwrap() as usize,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        expected_columns
            .into_iter()
            .map(|(start, end)| (2, start, 2, end))
            .collect::<Vec<_>>(),
        actual_ranges,
        "payload: {value}"
    );

    let rendered = value["rendered_text"].as_str().unwrap();
    for (_, start, _, end) in actual_ranges {
        assert!(
            rendered.contains(&format!("line 2:{start}-2:{end}")),
            "rendered: {rendered}"
        );
    }
}

#[test]
fn scan_usages_by_reference_includes_all_scala_overloads() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Unary.scala",
            r#"
package app

def compute(value: Int): Int = value
"#,
        )
        .file(
            "app/Binary.scala",
            r#"
package app

def compute(left: Int, right: Int): Int = left + right
"#,
        )
        .file(
            "app/Caller.scala",
            r#"
package app

object Caller {
  val unary = compute(1)
  val binary = compute(1, 2)
  val unrelated = other.compute("no")
}
"#,
        )
        .file(
            "other/Other.scala",
            r#"
package other

def compute(value: String): String = value
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["app.compute"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert_eq!(usage["status"], "found", "{value}");
    assert_eq!(usage["total_hits"], 2, "{value}");
    let snippets: Vec<&str> = usage["files"][0]["hits"]
        .as_array()
        .expect("Scala usage hits")
        .iter()
        .filter_map(|hit| hit["snippet"].as_str())
        .collect();
    assert!(
        snippets
            .iter()
            .any(|snippet| snippet.contains("compute(1)")),
        "missing unary overload call: {value}"
    );
    assert!(
        snippets
            .iter()
            .any(|snippet| snippet.contains("compute(1, 2)")),
        "missing binary overload call: {value}"
    );
    assert!(
        snippets
            .iter()
            .all(|snippet| !snippet.contains("other.compute")),
        "unrelated same-name method leaked into results: {value}"
    );
}

#[test]
fn scan_usages_by_reference_finds_inherited_scala_class_callables() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Services.scala",
            r#"
package app

class Base {
  def inherited(value: Int): Int = value
  def current: Int = 1
  def transform(value: Int): Int = value
}

class Child extends Base {
  val call = inherited(1)
  val property = current
  val eta: Int => Int = transform
}

class UnrelatedBase {
  def inherited(value: Int): Int = value
  def current: Int = 2
  def transform(value: Int): Int = value + 1
}

class UnrelatedChild extends UnrelatedBase {
  val unrelatedCall = inherited(2)
  val unrelatedProperty = current
  val unrelatedEta: Int => Int = transform
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, expected) in [
        ("app.Base.inherited", "val call = inherited(1)"),
        ("app.Base.current", "val property = current"),
        ("app.Base.transform", "val eta: Int => Int = transform"),
    ] {
        let args = serde_json::json!({"symbols": [symbol], "include_tests": true}).to_string();
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args)
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let usage = only_result(&value);
        assert_eq!(usage["status"], "found", "{value}");
        assert_eq!(usage["total_hits"], 1, "{value}");
        assert!(
            usage["files"][0]["hits"][0]["snippet"]
                .as_str()
                .is_some_and(|snippet| snippet.contains(expected)),
            "expected {expected:?}: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_finds_scala_lexical_outer_callables() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Owners.scala",
            r#"
package app

object Outer {
  def catalog(value: Int): Int = value
  class Inner {
    val call = catalog(1) // positive-lexical-outer
  }
  class Nearer {
    def catalog(value: Int): Int = value + 1
    val call = catalog(2) // negative-nearer-owner
  }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["app.Outer.catalog"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert_eq!(usage["status"], "found", "{value}");
    assert_eq!(usage["total_hits"], 1, "{value}");
    assert!(
        usage["files"][0]["hits"][0]["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("positive-lexical-outer")),
        "expected lexical outer call only: {value}"
    );
}

#[test]
fn scan_usages_by_reference_accepts_scala_default_and_repeated_arity() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Api.scala",
            r#"
package app

class Base {
  def doTest(text: String, result: String, settings: String = "default"): Unit = ()
  def collect(head: String, rest: String*): Unit = ()
}
class Child extends Base {
  doTest("text", "result")
  doTest()
  doTest("one", "two", "three", "four")
  collect("one")
  collect("one", "two", "three")
}
object SbtScalaSdkData {
  def apply(version: Option[String], language: String = "Scala", jars: Int = 0, docs: Int = 0, sources: Int = 0): String = "sdk"
}
object Use {
  val sdk = SbtScalaSdkData(Some("3.3"))
  val missing = SbtScalaSdkData()
  val excessive = SbtScalaSdkData(Some("3.3"), "Scala", 1, 2, 3, 4)
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, expected_hits) in [
        ("app.Base.doTest", 1),
        ("app.Base.collect", 2),
        ("app.SbtScalaSdkData.apply", 1),
    ] {
        let args = serde_json::json!({"symbols": [symbol], "include_tests": true}).to_string();
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args)
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let usage = only_result(&value);
        assert_eq!(usage["status"], "found", "{value}");
        assert_eq!(usage["total_hits"], expected_hits, "{value}");
    }
}

#[test]
fn scan_usages_by_reference_finds_scala_companion_apply_and_infix_calls() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Int.scala",
            r#"
package scala

class Int {
  def -(other: Int): Int = this
  def <(other: Int): Boolean = false
}
"#,
        )
        .file(
            "app/Factories.scala",
            r#"
package app

case class Box private (value: Int)

object Box {
  def apply(value: Int): Box = new Box(value)
}

object Factory {
  def apply(value: Int): Box = ???
}
"#,
        )
        .file(
            "app/Use.scala",
            r#"
package app

object Use {
  val factory = Factory(1)
  val box = Box(2)
  val difference = 3 - 1
  val comparison = 3 < 4
}
"#,
        )
        .file(
            "other/Numbers.scala",
            r#"
package other

class Number {
  def -(other: Number): Number = this
  def <(other: Number): Boolean = false
}

object NumberUse {
  def difference(left: Number, right: Number): Number = left - right
  def comparison(left: Number, right: Number): Boolean = left < right
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["app.Factory.apply","app.Box.apply","scala.Int.-","scala.Int.<"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(4, resolved_scan_count(&value), "payload: {value}");
    for usage in results(&value) {
        assert_eq!(usage["status"], "found", "payload: {value}");
        assert_eq!(usage["total_hits"], 1, "payload: {value}");
        assert_eq!(usage["files"][0]["path"], "app/Use.scala", "{value}");
    }
}

#[test]
fn scan_usages_by_reference_finds_scala_unqualified_type_roles() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Model.scala",
            r#"package model
class Extracted(val value: Int)
object Extracted { def unapply(value: Any): Option[Int] = None }
class Built(val value: Int)
abstract class Zero
final class Projected private (val value: Int)
object Projected { def apply(value: Int): Projected = new Projected(value) }
trait Growable { def +=(value: Int): Unit }
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.*
object Use {
  def extract(value: Any): Int = value match { case Extracted(found) => found; case _ => 0 } // mcp-extractor
  val built = Built(1) // mcp-universal
  val projected = Projected(2) // mcp-apply
  val zero = new Zero: // mcp-zero
    override def toString = "zero"
  def grow(target: Growable): Unit = target += 1 // mcp-infix
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, expected) in [
        ("model.Extracted", "mcp-extractor"),
        ("model.Built", "mcp-universal"),
        ("model.Projected.apply", "mcp-apply"),
        ("model.Zero", "mcp-zero"),
        ("model.Growable.+=", "mcp-infix"),
    ] {
        let args = serde_json::json!({"symbols": [symbol], "include_tests": true}).to_string();
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args)
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let usage = only_result(&value);
        assert_eq!(usage["status"], "found", "{symbol}: {value}");
        assert!(
            usage["files"].as_array().into_iter().flatten().any(|file| {
                file["hits"].as_array().into_iter().flatten().any(|hit| {
                    hit["snippet"]
                        .as_str()
                        .is_some_and(|snippet| snippet.contains(expected))
                })
            }),
            "{symbol} missing {expected:?}: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_finds_scala_structured_selection_roles() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            r#"
package app

case class Config(name: String)
case class GenericConfig[T](name: String, value: T)
object Marks { val START = "<" }
class Base { val marker = "base" }
class Child extends Base { val inherited = marker }
trait Api { def value: Int; def run(): Int }
enum Mode { case Active }
object Extractor { def unapply(value: String): Option[String] = Some(value) }
"#,
        )
        .file(
            "app/Use.scala",
            r#"
package app

object Use {
  val config = Config(name = "main")
  val generic = GenericConfig[Int](name = "generic", value = 1)
  val created = new GenericConfig[Int](name = "created", value = 2)
  val typed: Config = config
  val marked = s"${Marks.START}value"
  val mode = Mode.Active
  def selected(api: Api): Int = api.run() + api.value
  def extracted(value: String): String = value match { case Extractor(found) => found }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, expected) in [
        ("app.Config.name", "Config(name = \"main\")"),
        ("app.GenericConfig.name", "name = \"created\""),
        ("app.Base.marker", "val inherited = marker"),
        ("app.Marks.START", "Marks.START"),
        ("app.Api.run", "api.run()"),
        ("app.Api.value", "api.value"),
        ("app.Config", "val typed: Config"),
        ("app.Mode", "Mode.Active"),
        ("app.Extractor", "case Extractor(found)"),
    ] {
        let args = serde_json::json!({"symbols": [symbol], "include_tests": true}).to_string();
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args)
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let usage = only_result(&value);
        assert_eq!(usage["status"], "found", "{value}");
        let snippets = usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str());
        assert!(
            snippets
                .into_iter()
                .any(|snippet| snippet.contains(expected)),
            "expected {expected:?}: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_uses_parser_active_scala_package_context() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/collection/ArrayOps.scala",
            "package scala.collection\nclass ArrayOps(value: Int)\n",
        )
        .file(
            "scala/collection/immutable/ArraySeq.scala",
            r#"package scala.collection
package immutable
object ArraySeq {
  val value = new ArrayOps(1) // public-positive-package-context
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["scala.collection.ArrayOps.ArrayOps"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert_eq!(usage["status"], "found", "{value}");
    assert!(
        usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("public-positive-package-context")),
        "{value}"
    );
}

#[test]
fn scan_usages_by_reference_resolves_scala_package_alias_roots_without_ambiguity_leaks() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "root/api/Types.scala",
            "package root.api\nclass ActorContext\n",
        )
        .file(
            "decoy/api/Types.scala",
            "package decoy.api\nclass ActorContext\n",
        )
        .file(
            "collision/Api.scala",
            "package collision\nobject Api { class ActorContext }\n",
        )
        .file(
            "collision/Api/Types.scala",
            "package collision.Api\nclass ActorContext\n",
        )
        .file(
            "root/consumer/Use.scala",
            r#"package root.consumer
import root.{api => classic}
object Use {
  val context: classic.ActorContext = null // public-positive-package-alias
}
"#,
        )
        .file(
            "root/consumer/Ambiguous.scala",
            r#"package root.consumer
import root.{api => clash}
import decoy.{api => clash}
object Ambiguous {
  val context: clash.ActorContext = null // public-negative-conflicting-package-alias
}
"#,
        )
        .file(
            "root/consumer/Collision.scala",
            r#"package root.consumer
import collision.{Api => mixed}
object Collision {
  val context: mixed.ActorContext = null // public-negative-same-tier-package-singleton
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["root.api.ActorContext"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert_eq!(usage["status"], "found", "{value}");
    let snippets = usage["files"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .filter_map(|hit| hit["snippet"].as_str())
        .collect::<Vec<_>>();
    assert!(
        snippets
            .iter()
            .any(|snippet| snippet.contains("public-positive-package-alias")),
        "{value}"
    );
    assert!(
        snippets
            .iter()
            .all(|snippet| !snippet.contains("public-negative-conflicting-package-alias")),
        "{value}"
    );

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["collision.Api$.ActorContext"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert_eq!(usage["status"], "verified_absent", "{value}");
    assert!(
        usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .all(|snippet| !snippet.contains("public-negative-same-tier-package-singleton")),
        "{value}"
    );
}

#[test]
fn scan_usages_by_reference_finds_unique_scala_companion_method_values() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Token.scala",
            "package model\ncase class Token(value: Int)\n",
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.Token
object Use {
  def accept(value: Int, function: Int => Token): Token = function(value)
  def keep(value: Any): Any = value
  val contextual = accept(1, Token) // public-positive-contextual-method-value
  val inferred = Option(1).map(Token) // public-positive-unique-method-value
  val rejected = keep(Token) // public-negative-known-non-function
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["model.Token"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert_eq!(usage["status"], "found", "{value}");
    let snippets = usage["files"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .filter_map(|hit| hit["snippet"].as_str())
        .collect::<Vec<_>>();
    for marker in [
        "public-positive-contextual-method-value",
        "public-positive-unique-method-value",
    ] {
        assert!(
            snippets.iter().any(|snippet| snippet.contains(marker)),
            "expected {marker}: {value}"
        );
    }
    assert!(
        snippets
            .iter()
            .all(|snippet| !snippet.contains("public-negative-known-non-function")),
        "{value}"
    );
}

#[test]
fn scan_usages_by_reference_finds_same_file_scala_companion_wildcard_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("kyo/Chunk.scala", "package kyo\nclass Chunk[+A]\n")
        .file(
            "kyo/Batch.scala",
            r#"package kyo
object Batch:
    import internal.*
    def run[A, S](v: A): A =
        type Item = A | Int
        def expand(items: List[Item]) =
            Kyo.foreach(items) {
                case ToExpand[A @unchecked, S @unchecked](seq: Seq[Any], cont) =>
                    Kyo.foreach(seq)(v => v)
                case item => item
            }
        expand(Nil)
    end run
    object internal:
        case class Call[A](v: A) // public-negative-nested-package-wildcard
    end internal
end Batch
"#,
        )
        .file(
            "kyo/ai/Context.scala",
            r#"package kyo.ai
import Context.*
import kyo.*
case class Context(calls: Chunk[Call]):
    def assistantMessage(calls: Chunk[Call]): Context = this // public-positive-context-call
end Context
object Context:
    case class Call(id: String)
end Context
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["kyo.ai.Context$.Call"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert_eq!(usage["status"], "found", "{value}");
    assert!(
        usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("public-positive-context-call")),
        "{value}"
    );
    assert!(
        usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .all(|snippet| !snippet.contains("public-negative-nested-package-wildcard")),
        "{value}"
    );
}

#[test]
fn scan_usages_by_reference_resolves_exact_scala_field_chains() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Fields.scala",
            r#"package model
class Leaf(val token: Int)
class Middle(val leaf: Leaf)
class Base(val inherited: Middle)
class Child extends Base(new Middle(new Leaf(1))) {
  def inheritedBare: Int = inherited.leaf.token // positive-inherited-bare
  def inheritedShadow(inherited: other.Middle): Int = inherited.leaf.token // negative-shadow
}
object Stable { val middle: Middle = new Middle(new Leaf(2)) }
object Owners { final class State(var maximumHeapSize: Int) }
"#,
        )
        .file(
            "other/Fields.scala",
            "package other\nclass Leaf(val token: Int)\nclass Middle(val leaf: Leaf)\n",
        )
        .file(
            "dup/First.scala",
            "package dup\nclass Owner(val value: Int)\n",
        )
        .file(
            "dup/Second.scala",
            "package dup\nclass Owner(val value: Int)\n",
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.{Child, Middle, Owners, Stable}
object Use {
  def typed(middle: Middle): Int = middle.leaf.token // positive-typed
  def inherited(child: Child): Int = child.inherited.leaf.token // positive-inherited
  def stable: Int = Stable.middle.leaf.token // positive-stable
  def nested: Int = { val state = new Owners.State(1); state.maximumHeapSize } // positive-nested
  def localShadow(middle: other.Middle): Int = middle.leaf.token // negative-shadow
  def ambiguous(owner: dup.Owner): Int = owner.value // negative-ambiguous
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, expected) in [
        ("model.Middle.leaf", "positive-typed"),
        ("model.Leaf.token", "positive-stable"),
        ("model.Base.inherited", "positive-inherited-bare"),
        ("model.Owners$.State.maximumHeapSize", "positive-nested"),
    ] {
        let args = serde_json::json!({"symbols": [symbol], "include_tests": true}).to_string();
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args)
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let usage = only_result(&value);
        assert_eq!(usage["status"], "found", "{value}");
        let snippets = usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .collect::<Vec<_>>();
        assert!(
            snippets.iter().any(|snippet| snippet.contains(expected)),
            "expected {expected:?}: {value}"
        );
        assert!(
            snippets
                .iter()
                .all(|snippet| !snippet.contains("negative-shadow")),
            "local-shadow decoy leaked: {value}"
        );
    }

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["dup.Owner.value"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);
    assert!(
        usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .all(|snippet| !snippet.contains("negative-ambiguous")),
        "ambiguous source identity leaked: {value}"
    );
}

#[test]
fn scan_usages_by_reference_resolves_scala_call_initializer_receiver() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Console.scala",
            r#"
package app

class Editor
class ScalaLanguageConsole { def textSent(value: String): Unit = () }
class OtherConsole { def textSent(value: String): Unit = () }
object ScalaConsoleInfo { def getConsole(editor: Editor): ScalaLanguageConsole = new ScalaLanguageConsole }
object OtherInfo { def getConsole(editor: Editor): OtherConsole = new OtherConsole }

object Action {
  def run(editor: Editor): Unit = {
    val console = ScalaConsoleInfo.getConsole(editor)
    console.textSent("expected")
    val decoy = OtherInfo.getConsole(editor)
    decoy.textSent("other")
  }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["app.ScalaLanguageConsole.textSent"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);

    assert_eq!(usage["status"], "found", "{value}");
    assert_eq!(usage["total_hits"], 1, "{value}");
    assert!(
        usage["files"][0]["hits"][0]["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("console.textSent(\"expected\")")),
        "{value}"
    );
}

#[test]
fn scan_usages_by_reference_resolves_shared_scala_union_receiver_member() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/CompletionValue.scala",
            r#"package model
sealed trait CompletionValue { def insertText: Option[String] = None }
object CompletionValue {
  sealed trait Symbolic extends CompletionValue
  class Workspace extends Symbolic
  class Extension extends Symbolic
}
class Unrelated
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.CompletionValue.Workspace
import model.CompletionValue.Extension
import model.Unrelated
object Use {
  def shared(v: Workspace | Extension): Option[String] = v.insertText
  def rejected(v: Workspace | Unrelated): Option[String] = v.insertText
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["model.CompletionValue.insertText"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);

    assert_eq!(usage["status"], "found", "{value}");
    assert_eq!(usage["total_hits"], 1, "{value}");
    assert!(
        usage["files"][0]["hits"][0]["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("def shared")),
        "{value}"
    );
}

#[test]
fn scan_usages_by_location_does_not_expose_nested_scala_type_through_wildcard_import() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "kyo/Chunk.scala",
            r#"package kyo

sealed abstract class Chunk[+A]:
  final def dropLeft(n: Int): Chunk[A] = this
"#,
        )
        .file(
            "kyo/internal/Queue.scala",
            r#"package kyo.internal

object Queue:
  final class Chunk
"#,
        )
        .file(
            "kyo/Channel.scala",
            r#"package kyo

import kyo.internal.*

object Channel:
  def offerAll[A](initial: Chunk[A]): Chunk[A] =
    def loop(currentChunk: Chunk[A]): Chunk[A] =
      currentChunk.dropLeft(1)

    loop(initial)
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"kyo/Chunk.scala","line":4,"column":13}],"include_tests":true}"#,
        )
        .expect("location scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let usage = only_result(&value);
    assert_eq!("found", usage["status"], "payload: {value}");
    assert_eq!(Some(1), usage["total_hits"].as_u64(), "payload: {value}");
    assert!(
        usage["files"][0]["hits"][0]["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("currentChunk.dropLeft(1)")),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_labels_override_declarations_and_reports_resolved_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Base.java",
            r#"
package com.example;

public abstract class Base {
    public abstract void run(int value);



    public void run(int value, String unrelated) {}
}
"#,
        )
        .file(
            "com/example/Child.java",
            r#"
package com.example;

public class Child extends Base {
    @Override
    public void run(int value) {}
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let args = r#"{"symbols":["com.example.Child.run"],"include_tests":true}"#;
    let payload = service
        .call_tool_json("scan_usages_by_reference", args)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);

    assert_eq!("found", usage["status"]);
    assert_eq!("com.example.Child.run", usage["fq_name"]);
    assert_eq!("com/example/Child.java", usage["definition_path"]);
    assert!(
        usage["definition_line"].as_u64().is_some(),
        "payload: {value}"
    );

    let base = usage["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "com/example/Base.java")
        .unwrap_or_else(|| panic!("expected Base.java in files: {value}"));
    let hits = base["hits"].as_array().unwrap();
    assert!(
        hits.iter().any(|hit| {
            hit["kind"] == "override_declaration"
                && hit["snippet"]
                    .as_str()
                    .is_some_and(|snippet| snippet.contains("abstract void run(int value)"))
        }),
        "expected tagged abstract declaration hit: {value}"
    );
    assert!(
        hits.iter().all(|hit| {
            !hit["snippet"]
                .as_str()
                .unwrap_or_default()
                .contains("String unrelated")
        }),
        "unrelated overload must not be reported: {value}"
    );

    let rendered_payload = service
        .call_tool_payload_json("scan_usages_by_reference", args, RenderOptions::default())
        .unwrap();
    let rendered_value: Value = serde_json::from_str(&rendered_payload).unwrap();
    let rendered = rendered_value["rendered_text"]
        .as_str()
        .expect("rendered text");
    assert!(
        rendered.contains("resolved: com.example.Child.run (com/example/Child.java:"),
        "{rendered}"
    );
    assert!(rendered.contains("[override_declaration]"), "{rendered}");
}

#[test]
fn java_scan_usages_surfaces_find_bare_inherited_fields_without_local_shadows() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "p/Base.java",
            "package p;\npublic class Base {\n    protected static final int YEAR = 2026;\n}\n",
        )
        .file(
            "p/Child.java",
            r#"package p;
public class Child extends Base {
    int inherited() { return YEAR; } // positive-inherited-read
    int localShadow() {
        int YEAR = 1;
        return YEAR; // negative-local-shadow
    }
    int parameterShadow(int YEAR) {
        return YEAR; // negative-parameter-shadow
    }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (tool, args) in [
        (
            "scan_usages_by_reference",
            serde_json::json!({"symbols": ["p.Base.YEAR"], "include_tests": true}),
        ),
        (
            "scan_usages_by_location",
            serde_json::json!({
                "targets": [{"path": "p/Base.java", "line": 3}],
                "include_tests": true,
            }),
        ),
    ] {
        let payload = service
            .call_tool_json(tool, &args.to_string())
            .expect("scan succeeds");
        let value: Value = serde_json::from_str(&payload).expect("valid response");
        let usage = only_result(&value);

        assert_eq!("found", usage["status"], "{tool}: {value}");
        assert_eq!(1, usage["total_hits"], "{tool}: {value}");
        let snippets: Vec<_> = usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .collect();
        assert!(
            snippets
                .iter()
                .any(|snippet| snippet.contains("positive-inherited-read")),
            "{tool}: {value}"
        );
        assert!(
            snippets
                .iter()
                .all(|snippet| !snippet.contains("negative-")),
            "{tool}: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_finds_bare_inherited_java_methods_without_self_confusion() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "p/Base.java",
            "package p;\npublic class Base {\n    protected void ping(String left, String right) {}\n}\n",
        )
        .file(
            "p/Child.java",
            r#"package p;
public class Child extends Base {
    void inherited() {
        ping("left", "right"); // positive-inherited-call
    }
}
"#,
        )
        .file(
            "p/OverrideChild.java",
            r#"package p;
public class OverrideChild extends Base {
    @Override
    protected void ping(String left, String right) {}
    void selfCall() {
        ping("left", "right"); // negative-self-call
    }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["p.Base.ping"],"include_tests":true}"#,
        )
        .expect("scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let usage = only_result(&value);

    assert_eq!("found", usage["status"], "{value}");
    assert_eq!(2, usage["total_hits"], "{value}");
    let hits: Vec<_> = usage["files"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .collect();
    assert!(
        hits.iter()
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("positive-inherited-call")),
        "{value}"
    );
    assert!(
        hits.iter()
            .filter_map(|hit| hit["line"].as_u64())
            .all(|line| line != 6),
        "{value}"
    );
    assert_eq!(1, usage["unproven_hits"], "{value}");
}

#[test]
fn java_scan_usages_separates_interface_and_concrete_method_ranges() {
    let runner = r#"package com.example;
public class Runner {
    Handler makeAnonymous() {
        return new Handler() {
            @Override public String handle(String value) { return value; }
        };
    }
    String run() {
        Handler handler = new ConsoleHandler();
        ConsoleHandler direct = new ConsoleHandler();
        return handler.handle(" Ada ") + ":" + direct.handle(" Grace ") + ":" + makeAnonymous().handle(" Linus ");
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Handler.java",
            "package com.example; public interface Handler { String handle(String value); }\n",
        )
        .file(
            "com/example/ConsoleHandler.java",
            "package com.example; public class ConsoleHandler implements Handler { @Override public String handle(String value) { return value.trim(); } }\n",
        )
        .file("com/example/Runner.java", runner)
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let return_line = runner
        .lines()
        .find(|line| line.contains("return handler.handle"))
        .expect("return line");
    let ranges = return_line
        .match_indices(".handle")
        .map(|(byte, _)| {
            let start = return_line[..byte].chars().count() + 2;
            (start, start + "handle".chars().count())
        })
        .collect::<Vec<_>>();
    assert_eq!(3, ranges.len());

    for (symbol, expected_ranges, expected_total_hits) in [
        ("com.example.Handler.handle", vec![ranges[0], ranges[2]], 3),
        ("com.example.ConsoleHandler.handle", vec![ranges[1]], 2),
    ] {
        let payload = service
            .call_tool_json(
                "scan_usages_by_reference",
                &serde_json::json!({"symbols": [symbol], "include_tests": true}).to_string(),
            )
            .expect("scan succeeds");
        let value: Value = serde_json::from_str(&payload).expect("valid response");
        let usage = only_result(&value);
        assert_eq!("found", usage["status"], "{symbol}: {value}");
        assert_eq!(
            expected_total_hits, usage["total_hits"],
            "{symbol}: {value}"
        );
        assert_eq!(0, usage["unproven_hits"], "{symbol}: {value}");

        let runner_hits = usage["files"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|file| file["path"] == "com/example/Runner.java")
            .and_then(|file| file["hits"].as_array())
            .expect("Runner.java hits");
        let actual_ranges = runner_hits
            .iter()
            .map(|hit| {
                (
                    hit["column"].as_u64().unwrap() as usize,
                    hit["end_column"].as_u64().unwrap() as usize,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(expected_ranges, actual_ranges, "{symbol}: {value}");
    }
}

#[test]
fn scan_usages_java_varargs_calls_stay_narrow() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "p/Target.java",
            r#"package p;
public class Target<T> {
    public void join(String left) {}
    public void join(String left, String right, String... rest) {}
    public Target(String left) {}
    public Target(String left, String right, String... rest) {}
}
"#,
        )
        .file(
            "p/Consumer.java",
            r#"package p;
public class Consumer {
    void call(Target target) {
        target.join("a", "b", "c"); // positive-varargs-expanded-method
        target.join("a", "b", new String[]{"c"}); // positive-varargs-array-method
        target.join("a"); // negative-non-varargs-method

        new Target<>("a", "b", "c"); // positive-varargs-expanded-constructor
        new Target<>("a", "b", new String[]{"c"}); // positive-varargs-array-constructor
        new Target<>("a"); // negative-non-varargs-constructor
    }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let method_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"p/Target.java","line":4}],"include_tests":true}"#,
        )
        .expect("method scan succeeds");
    let method_value: Value = serde_json::from_str(&method_payload).expect("valid response");
    let method_usage = only_result(&method_value);
    assert_eq!("found", method_usage["status"], "{method_value}");
    assert_eq!(2, method_usage["total_hits"], "{method_value}");
    let method_hits: Vec<_> = method_usage["files"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .collect();
    assert!(
        method_hits
            .iter()
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("positive-varargs-expanded-method")),
        "{method_value}"
    );
    assert!(
        method_hits
            .iter()
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("positive-varargs-array-method")),
        "{method_value}"
    );
    assert!(
        method_hits
            .iter()
            .filter_map(|hit| hit["line"].as_u64())
            .all(|line| line != 7),
        "{method_value}"
    );

    let constructor_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"p/Target.java","line":6}],"include_tests":true}"#,
        )
        .expect("constructor scan succeeds");
    let constructor_value: Value =
        serde_json::from_str(&constructor_payload).expect("valid response");
    let constructor_usage = only_result(&constructor_value);
    assert_eq!("found", constructor_usage["status"], "{constructor_value}");
    assert_eq!(2, constructor_usage["total_hits"], "{constructor_value}");
    let constructor_hits: Vec<_> = constructor_usage["files"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .collect();
    assert!(
        constructor_hits
            .iter()
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("positive-varargs-expanded-constructor")),
        "{constructor_value}"
    );
    assert!(
        constructor_hits
            .iter()
            .filter_map(|hit| hit["snippet"].as_str())
            .any(|snippet| snippet.contains("positive-varargs-array-constructor")),
        "{constructor_value}"
    );
    assert!(
        constructor_hits
            .iter()
            .filter_map(|hit| hit["line"].as_u64())
            .all(|line| line != 11),
        "{constructor_value}"
    );
}

#[test]
fn scan_usages_distinguishes_resolved_zero_from_unresolved_symbol() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Greeter.java",
            "public class Greeter {\n    public String unused() { return \"hi\"; }\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let resolved_payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.unused"],"include_tests":true}"#,
        )
        .unwrap();
    let resolved: Value = serde_json::from_str(&resolved_payload).unwrap();
    assert_eq!(1, resolved_scan_count(&resolved), "payload: {resolved}");
    assert_eq!(
        0,
        status_count(&resolved, "not_found"),
        "payload: {resolved}"
    );
    let entry = only_result(&resolved);
    assert_eq!("verified_absent", entry["status"]);
    assert_eq!(0, entry["total_hits"].as_u64().unwrap());

    let unresolved_payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.missing"],"include_tests":true}"#,
        )
        .unwrap();
    let unresolved: Value = serde_json::from_str(&unresolved_payload).unwrap();
    assert_eq!(0, resolved_scan_count(&unresolved), "payload: {unresolved}");
    assert_eq!(
        1,
        status_count(&unresolved, "not_found"),
        "payload: {unresolved}"
    );
    let entry = only_result(&unresolved);
    assert_eq!("not_found", entry["status"]);
    assert_eq!("Greeter.missing", entry["input"]);
    assert!(
        entry["message"]
            .as_str()
            .is_some_and(|note| note.contains("no symbol matched")),
        "payload: {unresolved}"
    );
}

#[test]
fn scan_usages_python_payload_includes_rendered_diagnostics_and_zero_notes() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Greeter.java",
            "public class Greeter {\n    public String unused() { return \"hi\"; }\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let unresolved_payload = service
        .call_tool_payload_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.missing"],"include_tests":true}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let unresolved: Value = serde_json::from_str(&unresolved_payload).unwrap();
    let rendered = unresolved["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("not_found"), "{rendered}");
    assert!(rendered.contains("Greeter.missing"), "{rendered}");
    assert!(rendered.contains("no symbol matched"), "{rendered}");
    assert!(!rendered.trim().eq("No usages found."), "{rendered}");

    let zero_payload = service
        .call_tool_payload_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.unused"],"include_tests":true}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let zero: Value = serde_json::from_str(&zero_payload).unwrap();
    let rendered = zero["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("Greeter.unused: verified_absent"),
        "{rendered}"
    );
    assert!(
        rendered.contains("resolved symbol; no external usage sites found"),
        "{rendered}"
    );
    assert!(
        rendered.contains("Scope: analyzed source including test files; whole analyzed workspace."),
        "{rendered}"
    );
}

#[test]
fn scan_usages_verified_absent_names_filters_and_followups() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Target.java",
            "package src;\npublic class Target {\n    public void unused() {}\n}\n",
        )
        .file(
            "src/Scoped.java",
            "package src;\npublic class Scoped {}\n",
        )
        .file(
            "src/TargetTest.java",
            "package src;\npublic class TargetTest {\n    public void calls() { new Target().unused(); }\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_payload_json(
            "scan_usages_by_reference",
            r#"{"symbols":["src.Target.unused"],"include_tests":false,"paths":["src/Scoped.java"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let rendered = value["rendered_text"].as_str().expect("rendered text");

    let structured = &value["structured"];
    assert_eq!("verified_absent", only_result(structured)["status"]);
    assert_eq!(false, structured["scope"]["include_tests"]);
    assert_eq!(false, structured["scope"]["whole_workspace"]);
    assert_eq!("src/Scoped.java", structured["scope"]["paths"][0]);
    assert!(
        rendered.contains(
            "Scope: production analyzed source only (include_tests=false); effective paths: src/Scoped.java."
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("retry with include_tests=true to include test usages."),
        "{rendered}"
    );
    assert!(
        rendered.contains("drop or widen paths to search the whole analyzed workspace."),
        "{rendered}"
    );
    assert!(
        rendered.contains("framework-invoked entrypoint"),
        "{rendered}"
    );
}

#[test]
fn scan_usages_scope_reports_effective_filters_and_ignored_inputs() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Target.java",
            "public class Target {\n    public void unused() {}\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_payload_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Target.unused"],"include_tests":true,"paths":["   ","["]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let structured = &value["structured"];

    assert_eq!(true, structured["scope"]["whole_workspace"], "{value}");
    assert_eq!(2, structured["scope"]["ignored_paths"], "{value}");
    assert!(structured["scope"]["paths"].is_null(), "{value}");
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("whole analyzed workspace"), "{rendered}");
    assert!(
        rendered
            .contains("2 supplied path filters were ignored because they were blank or invalid"),
        "{rendered}"
    );
}

#[test]
fn scan_usages_scope_paths_are_bounded_by_the_response_budget() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Target.java",
            "public class Target {\n    public void unused() {}\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let mut paths = (0..200)
        .map(|index| format!("missing/{index:03}-{}.java", "x".repeat(80)))
        .collect::<Vec<_>>();
    paths[0] = format!("missing/{}.java", "x".repeat(20_000));
    let arguments = serde_json::json!({
        "symbols": ["Target.unused"],
        "include_tests": true,
        "paths": paths,
    })
    .to_string();

    let payload = service
        .call_tool_json("scan_usages_by_reference", &arguments)
        .unwrap();
    assert!(
        payload.len() <= SCAN_USAGES_RESPONSE_BUDGET_BYTES,
        "payload should stay within scan_usages budget, got {} bytes",
        payload.len()
    );
    let value: Value = serde_json::from_str(&payload).unwrap();
    let scope_paths = value["scope"]["paths"].as_array().unwrap();
    assert_eq!(5, scope_paths.len());
    assert!(scope_paths[0].as_str().unwrap().ends_with('…'));
    assert!(scope_paths[0].as_str().unwrap().len() < 300);
    assert_eq!(195, value["scope"]["paths_omitted"]);
}

#[test]
fn scan_usages_truncated_zero_hit_result_is_partial_failure_with_candidate_sample() {
    let mut project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {}\n",
        );
    for idx in 0..1005 {
        project = project.file(
            format!("aaa/Decoy{idx:04}.php"),
            "<?php\nnamespace Decoy;\nfunction noop() {}\n",
        );
    }
    let project = project
        .file(
            "zzz/RealCaller.php",
            "<?php\nnamespace Later;\nfunction build(): \\App\\Service { return new \\App\\Service(); }\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["App.Service"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
    assert_eq!(0, status_count(&value, "failure"), "payload: {value}");
    assert_eq!(true, value["summary"]["partial"], "payload: {value}");
    let failure = only_result(&value);
    assert_eq!("unverified_absent", failure["status"]);
    assert!(
        failure["complete"]
            .as_bool()
            .map(|value| !value)
            .unwrap_or(false)
    );
    assert!(
        failure["absence_caveats"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "candidate_files_truncated")),
        "payload: {value}"
    );
    assert!(
        failure["candidate_files_sample"]["scanned"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "payload: {value}"
    );
    assert!(
        failure["candidate_files_sample"]["omitted"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "payload: {value}"
    );
    assert!(
        failure["candidate_files_sample"]["omitted_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "payload: {value}"
    );
    assert!(
        failure["message"]
            .as_str()
            .is_some_and(|message| message.contains("candidate files were truncated")),
        "payload: {value}"
    );
    assert!(
        failure["notes"]
            .as_array()
            .is_none_or(|notes| notes.iter().all(|note| !note
                .as_str()
                .unwrap_or_default()
                .contains("Candidate file set was truncated"))),
        "truncation recovery should have one prose owner: {value}"
    );
}

#[test]
fn scan_usages_lines_mode_clusters_repeated_enclosing_hits_and_preserves_sparse_snippets() {
    let repeated_calls = (0..101)
        .map(|idx| format!("        Service.target(); // {idx}\n"))
        .collect::<String>();
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Service.java",
            "public class Service {\n    public static void target() {}\n}\n",
        )
        .file(
            "BulkCaller.java",
            format!(
                "public class BulkCaller {{\n    public void run() {{\n{repeated_calls}    }}\n}}\n"
            ),
        )
        .file(
            "SingleA.java",
            "public class SingleA {\n    public void run() { Service.target(); }\n}\n",
        )
        .file(
            "SingleB.java",
            "public class SingleB {\n    public void run() { Service.target(); }\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Service.target"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let usage = only_result(&value);
    assert_eq!("lines", usage["rendering"], "payload: {value}");
    assert_eq!(103, usage["total_hits"], "payload: {value}");

    let bulk = usage["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "BulkCaller.java")
        .unwrap_or_else(|| panic!("missing BulkCaller.java: {value}"));
    let bulk_hits = bulk["hits"].as_array().unwrap();
    assert_eq!(1, bulk_hits.len(), "payload: {value}");
    assert_eq!(101, bulk_hits[0]["hit_count"], "payload: {value}");
    assert_eq!("3-103", bulk_hits[0]["line_range"], "payload: {value}");
    assert!(bulk_hits[0]["snippet"].is_null(), "payload: {value}");
    for field in ["column", "end_line", "end_column"] {
        assert!(bulk_hits[0][field].is_null(), "payload: {value}");
    }

    for path in ["SingleA.java", "SingleB.java"] {
        let file = usage["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|file| file["path"] == path)
            .unwrap_or_else(|| panic!("missing {path}: {value}"));
        let hit = &file["hits"].as_array().unwrap()[0];
        assert!(
            hit["snippet"]
                .as_str()
                .is_some_and(|snippet| snippet.contains("Service.target()")),
            "payload: {value}"
        );
        for field in ["column", "end_line", "end_column"] {
            assert!(hit[field].is_null(), "payload: {value}");
        }
    }
}

fn assert_ruby_user_save_scan_usages_hit(user_call: &str, account_call: &str, expected_hit: &str) {
    let source = format!(
        r#"
class User
  def save
  end
end

class Account
  def save
  end
end

class App
  def run
    user = User.new
    {user_call}

    account = Account.new
    {account_call}
  end
end
"#
    );
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("app/user.rb", source.clone())
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["User.save"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "not_found"), "payload: {value}");
    assert_eq!(0, status_count(&value, "ambiguous"), "payload: {value}");
    assert_eq!(0, status_count(&value, "failure"), "payload: {value}");
    let usage = only_result(&value);
    assert_eq!("User.save", usage["symbol"], "payload: {value}");
    assert_eq!(1, usage["total_hits"], "payload: {value}");
    let hits = usage["files"][0]["hits"].as_array().unwrap();
    let hit = hits
        .iter()
        .find(|hit| {
            hit["snippet"]
                .as_str()
                .unwrap_or_default()
                .contains(expected_hit)
        })
        .unwrap_or_else(|| panic!("expected {expected_hit} hit: {value}"));
    let line = source
        .lines()
        .nth(hit["line"].as_u64().unwrap() as usize - 1)
        .expect("hit line");
    let expected_column = line.rfind("save").expect("save token") + 1;
    assert_eq!(hit["column"], expected_column, "payload: {value}");
    assert_eq!(
        hit["end_column"],
        expected_column + "save".len(),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_mcp_call_uses_ruby_receiver_aware_resolution() {
    assert_ruby_user_save_scan_usages_hit("user.save", "account.save", "user.save");
}

#[test]
fn scan_usages_mcp_call_resolves_ruby_public_send_symbol_dispatch() {
    assert_ruby_user_save_scan_usages_hit(
        "user.public_send(:save)\n    user.public_send(:missing, :save)",
        "account.public_send(:save)",
        "user.public_send(:save)",
    );
}

#[test]
fn scan_usages_mcp_call_selects_static_quoted_ruby_symbol_content() {
    assert_ruby_user_save_scan_usages_hit(
        "user.public_send(:\"save\")",
        "account.public_send(:\"save\")",
        "user.public_send(:\"save\")",
    );
}

#[test]
fn scan_usages_location_selects_ruby_macro_generated_methods() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/product.rb",
            r#"class Product
  attr_reader :name
  alias_method :label, :name

  def self.featured
    new("featured")
  end

  def summary
    label
  end
end
"#,
        )
        .file(
            "app/catalog.rb",
            r#"require "lib/product"

product = Product.featured
product.name
product.label
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    for (line, column, symbol, expected_snippets) in [
        (
            2,
            16,
            "Product.name",
            ["alias_method :label, :name", "product.name"].as_slice(),
        ),
        (
            3,
            17,
            "Product.label",
            ["label", "product.label"].as_slice(),
        ),
    ] {
        let args = serde_json::json!({
            "targets": [{
                "path": "lib/product.rb",
                "line": line,
                "column": column,
            }],
            "include_tests": true,
        });
        let payload = service
            .call_tool_json("scan_usages_by_location", &args.to_string())
            .expect("scan succeeds");
        let value: Value = serde_json::from_str(&payload).expect("valid response");
        let result = only_result(&value);

        assert_eq!("found", result["status"], "payload: {value}");
        assert_eq!(symbol, result["symbol"], "payload: {value}");
        let snippets: Vec<_> = result["files"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["snippet"].as_str())
            .collect();
        for expected in expected_snippets {
            assert!(
                snippets.iter().any(|snippet| snippet.contains(expected)),
                "expected {expected} usage: {value}"
            );
        }
        if symbol == "Product.name" {
            let exact_hits: Vec<_> = result["files"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|file| file["hits"].as_array().into_iter().flatten())
                .collect();
            for (snippet, column, end_column) in [
                ("alias_method :label, :name", 25, 29),
                ("product.name", 9, 13),
            ] {
                let hit = exact_hits
                    .iter()
                    .find(|hit| {
                        hit["snippet"]
                            .as_str()
                            .is_some_and(|text| text.contains(snippet))
                    })
                    .unwrap_or_else(|| panic!("missing {snippet}: {value}"));
                assert_eq!(hit["column"], column, "payload: {value}");
                assert_eq!(hit["end_column"], end_column, "payload: {value}");
            }
        }
    }

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"lib/product.rb","line":3,"column":25}],"include_tests":true}"#,
        )
        .expect("scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    assert_eq!(
        "not_found",
        only_result(&value)["status"],
        "payload: {value}"
    );
}

#[test]
fn scan_usages_mcp_call_surfaces_ruby_unproven_sites() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/user.rb",
            r#"
class User
  def save
  end
end

class App
  def run(obj)
    obj.save
    send(:save)
  end
end
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["User.save"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "failure"), "payload: {value}");
    assert_eq!(0, status_count(&value, "not_found"), "payload: {value}");
    let usage = only_result(&value);
    assert_eq!("User.save", usage["symbol"]);
    assert_eq!(0, usage["total_hits"], "payload: {value}");
    assert_eq!(2, usage["unproven_hits"], "payload: {value}");
    assert!(
        usage["unproven_files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()),
        "unproven sites must be rendered: {value}"
    );
}

#[test]
fn scan_usages_reports_java_untyped_receiver_as_unproven() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Target.java",
            r#"
public class Target {
    public void save() {}
}
"#,
        )
        .file(
            "Caller.java",
            r#"
public class Caller {
    public void run(Object obj) {
        obj.save();
    }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Target.save"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "failure"), "payload: {value}");
    let usage = only_result(&value);
    assert_eq!("Target.save", usage["symbol"]);
    assert_eq!(0, usage["total_hits"], "payload: {value}");
    assert_eq!(1, usage["unproven_hits"], "payload: {value}");

    let rendered_payload = service
        .call_tool_payload_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Target.save"],"include_tests":true}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let rendered_value: Value = serde_json::from_str(&rendered_payload).unwrap();
    let rendered = rendered_value["rendered_text"]
        .as_str()
        .expect("rendered text");
    assert!(
        rendered.contains(
            "message: no PROVEN usage sites, but 1 unproven candidate usage(s) found across 1 file(s); inspect these before concluding absence"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("narrow `paths` to a relevant candidate file"),
        "{rendered}"
    );
    assert!(!rendered.contains("intended caller"), "{rendered}");
    assert!(
        rendered.find("message: no PROVEN usage sites").unwrap()
            < rendered.find("unproven matches:").unwrap(),
        "candidate guidance should lead before raw candidates: {rendered}"
    );
}

#[test]
fn scan_usages_reports_cpp_template_receiver_as_unproven() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.cpp",
            r#"
struct Target {
    void save(int value) {}
};

template <typename T>
void call(T value) {
    value.save(1);
}

void entry(Target target) {
    call(target);
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Target.save"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "failure"), "payload: {value}");
    let usage = only_result(&value);
    assert_eq!(0, usage["total_hits"], "payload: {value}");
    assert_eq!(1, usage["unproven_hits"], "payload: {value}");
}

#[test]
fn scan_usages_cpp_excludes_out_of_line_definitions_from_external_hits() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/service.h",
            r#"#pragma once
namespace example {
int compute(int value);
struct Service {
    int run(int value);
};
}
"#,
        )
        .file(
            "src/service.cpp",
            r#"#include "service.h"
namespace example {
int compute(int value) { return value + 1; }
int Service::run(int value) { return compute(value); }
}
"#,
        )
        .file(
            "src/main.cpp",
            r#"#include "service.h"
int use(example::Service& service) {
    return service.run(example::compute(1));
}
"#,
        )
        .file(
            "src/unresolved.cpp",
            "int Service::run(int value) { return value; }\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    for (target, expected_total, definition_line, expected_column, token_len) in [
        (
            r#"{"path":"include/service.h","line":3,"column":5,"symbol":"example.compute"}"#,
            2,
            3,
            33,
            7,
        ),
        (
            r#"{"path":"include/service.h","line":5,"column":9,"symbol":"example.Service.run"}"#,
            1,
            4,
            20,
            3,
        ),
    ] {
        let payload = service
            .call_tool_json(
                "scan_usages_by_location",
                &format!(r#"{{"targets":[{target}],"include_tests":true}}"#),
            )
            .expect("C++ location scan succeeds");
        let value: Value = serde_json::from_str(&payload).expect("valid response");
        let result = only_result(&value);

        assert_eq!("found", result["status"], "payload: {value}");
        assert_eq!(expected_total, result["total_hits"], "payload: {value}");
        assert_eq!(1, result["definition_sites_excluded"], "payload: {value}");
        assert_eq!("src/main.cpp", result["files"][0]["path"], "{value}");
        assert_eq!(3, result["files"][0]["hits"][0]["line"], "{value}");
        assert_eq!(
            expected_column, result["files"][0]["hits"][0]["column"],
            "{value}"
        );
        assert_eq!(
            expected_column + token_len,
            result["files"][0]["hits"][0]["end_column"],
            "{value}"
        );
        assert!(
            result["files"]
                .as_array()
                .expect("files")
                .iter()
                .all(|file| file["path"] != "src/service.cpp"
                    || file["hits"]
                        .as_array()
                        .expect("hits")
                        .iter()
                        .all(|hit| hit["line"] != definition_line)),
            "out-of-line definition leaked into external usages: {value}"
        );
    }

    let unresolved_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"include/service.h","line":5,"column":9,"symbol":"example.Service.run"}],"paths":["src/unresolved.cpp"],"include_tests":true}"#,
        )
        .expect("path-scoped unresolved definition scan succeeds");
    let unresolved_value: Value =
        serde_json::from_str(&unresolved_payload).expect("valid response");
    let unresolved = only_result(&unresolved_value);
    assert_eq!(0, unresolved["total_hits"], "{unresolved_value}");
    assert_eq!(0, unresolved["unproven_hits"], "{unresolved_value}");
    assert_eq!(
        1, unresolved["definition_sites_excluded"],
        "{unresolved_value}"
    );
    assert!(
        unresolved["files"].as_array().is_none_or(Vec::is_empty),
        "unresolved definition must not render as a usage row: {unresolved_value}"
    );
}

#[test]
fn cpp_string_literal_overload_is_narrow_at_public_location_boundaries() {
    let header = r#"#pragma once
namespace precision {
int select(int value);
int select(const char* value);
}
"#;
    let implementation = r#"#include "worker.h"
namespace precision {
int select(int value) { return value; }
int select(const char* value) { return value[0]; }
}
"#;
    let consumer = r#"#include "worker.h"
int consume() {
    return precision::select("name");
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/worker.h", header)
        .file("src/worker.cpp", implementation)
        .file("src/consumer.cpp", consumer)
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let call_line = "    return precision::select(\"name\");";
    let definitions_payload = service
        .call_tool_json(
            "get_definitions_by_location",
            &serde_json::json!({
                "references": [{
                    "path": "src/consumer.cpp",
                    "line": line_of(consumer, call_line),
                    "column": call_line.find("select").unwrap() + 1,
                }]
            })
            .to_string(),
        )
        .expect("definition lookup succeeds");
    let definitions: Value = serde_json::from_str(&definitions_payload).unwrap();
    let definition_result = &definitions["results"][0];
    assert_eq!("resolved", definition_result["status"], "{definitions}");
    assert_eq!(
        1,
        definition_result["definitions"].as_array().unwrap().len()
    );
    assert_eq!(
        "src/worker.cpp", definition_result["definitions"][0]["path"],
        "{definitions}"
    );
    assert!(
        definition_result["definitions"][0]["signature"]
            .as_str()
            .is_some_and(|signature| signature.contains("const char")),
        "{definitions}"
    );

    for (declaration_line, expected_status, expected_hits) in [
        ("int select(int value);", "verified_absent", 0),
        ("int select(const char* value);", "found", 1),
    ] {
        let payload = service
            .call_tool_json(
                "scan_usages_by_location",
                &serde_json::json!({
                    "targets": [{
                        "path": "include/worker.h",
                        "line": line_of(header, declaration_line),
                        "column": declaration_line.find("select").unwrap() + 1,
                    }],
                    "include_tests": true,
                })
                .to_string(),
            )
            .expect("usage scan succeeds");
        let value: Value = serde_json::from_str(&payload).unwrap();
        let result = only_result(&value);
        assert_eq!(expected_status, result["status"], "{value}");
        assert_eq!(expected_hits, result["total_hits"], "{value}");
        if expected_hits == 1 {
            assert_eq!("src/consumer.cpp", result["files"][0]["path"], "{value}");
            assert_eq!(
                line_of(consumer, call_line),
                result["files"][0]["hits"][0]["line"],
                "{value}"
            );
        }
    }
}

#[test]
fn scan_usages_cpp_macro_failure_is_actionable_and_hides_strategy_details() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("defs.h", "#define TEST_DECLARE(name) int name\n")
        .file(
            "uses.cpp",
            r#"
#include "defs.h"

void run() {
    TEST_DECLARE(value);
}
"#,
        )
        .file("actual.cpp", "void callable() {}\n")
        .file("wrong.h", "#define OTHER_MACRO 1\n")
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["TEST_DECLARE"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let failure = only_result(&value);

    assert_eq!("failure", failure["status"], "payload: {value}");
    assert_eq!(
        "unsupported_target_shape", failure["reason_kind"],
        "payload: {value}"
    );
    let message = failure["message"].as_str().expect("failure message");
    assert!(message.contains("C/C++ macro"), "payload: {value}");
    assert!(message.contains("query_code"), "payload: {value}");
    assert!(
        message.contains("syntactic invocation candidates"),
        "payload: {value}"
    );
    assert!(
        !message.contains("CppUsageGraphStrategy"),
        "payload: {value}"
    );
    assert!(failure.get("strategy").is_none(), "payload: {value}");

    let anchored_payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["wrong.h#TEST_DECLARE"],"include_tests":true}"#,
        )
        .unwrap();
    let anchored_value: Value = serde_json::from_str(&anchored_payload).unwrap();
    let anchored = only_result(&anchored_value);
    assert_eq!("not_found", anchored["status"], "payload: {anchored_value}");
    let anchored_message = anchored["message"].as_str().expect("not-found message");
    assert!(
        anchored_message.contains("C/C++ macro"),
        "payload: {anchored_value}"
    );
    assert!(
        anchored_message.contains("query_code"),
        "payload: {anchored_value}"
    );
    assert!(
        !anchored_message.contains("bare name"),
        "macro retry must not recommend the known-bad bare selector: {anchored_value}"
    );

    let ordinary_payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["wrong.h#callable"],"include_tests":true}"#,
        )
        .unwrap();
    let ordinary_value: Value = serde_json::from_str(&ordinary_payload).unwrap();
    let ordinary = only_result(&ordinary_value);
    assert_eq!("not_found", ordinary["status"], "payload: {ordinary_value}");
    assert!(
        ordinary["message"]
            .as_str()
            .is_some_and(|message| message.contains("bare name")),
        "ordinary wrong-file selector should keep its recovery hint: {ordinary_value}"
    );
}

#[test]
fn scan_usages_accepts_location_target_without_symbols() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Greeter.java",
            "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
        )
        .file(
            "Caller.java",
            "public class Caller {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"Greeter.java","line":2,"column":19}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, results(&value).len(), "payload: {value}");
    assert_eq!(0, status_count(&value, "not_found"));
    assert_eq!(0, status_count(&value, "failure"));
}

#[test]
fn scan_usages_by_location_matches_ruby_mixin_benchmark_cases() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/billing/auditable.rb",
            r#"module Billing
  module Auditable
    def audit
      "audit"
    end
  end
end
"#,
        )
        .file(
            "lib/billing/formatting.rb",
            r#"module Billing
  module Formatting
    def total_label
      "from-prepended-formatting"
    end
  end
end
"#,
        )
        .file(
            "lib/billing/findable.rb",
            r#"module Billing
  module Findable
    def find(id)
      "found-#{id}"
    end
  end
end
"#,
        )
        .file(
            "lib/billing/invoice.rb",
            r#"require_relative "auditable"
require_relative "formatting"

module Billing
  class Invoice
    include Auditable
    prepend Formatting

    def total_label
      "from-invoice"
    end

    def self.build
      Invoice.new
    end
  end
end
"#,
        )
        .file(
            "lib/billing/user.rb",
            r#"require_relative "findable"

module Billing
  class User
    extend Findable
  end

  class LegacyUser
    include Findable
  end
end
"#,
        )
        .file(
            "app/report.rb",
            r#"require_relative "../lib/billing/invoice"
require_relative "../lib/billing/user"

class InvoiceReport
  def render
    invoice = Billing::Invoice.build
    invoice.audit
    invoice.total_label
    Billing::User.find(42)
    Billing::LegacyUser.new.find(7)
    invoice.public_send(:audit)
  end
end
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"lib/billing/auditable.rb","line":3,"column":9},{"path":"lib/billing/formatting.rb","line":3,"column":9},{"path":"lib/billing/findable.rb","line":3,"column":9}],"include_tests":true}"#,
        )
        .expect("scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let results = results(&value);

    assert_eq!(3, results.len(), "payload: {value}");
    for (symbol, expected_hits) in [
        ("Billing$Auditable.audit", 2),
        ("Billing$Formatting.total_label", 1),
        ("Billing$Findable.find", 2),
    ] {
        assert!(
            results.iter().any(|result| {
                result["symbol"] == symbol
                    && result["status"] == "found"
                    && result["total_hits"] == expected_hits
            }),
            "missing {symbol}: {value}"
        );
    }
}

#[test]
fn scan_usages_by_location_traverses_declarationless_ruby_loaders() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/greeter.rb",
            r#"class Greeter
  def hello
    "hello"
  end
end
"#,
        )
        .file(
            "lib/loader.rb",
            r#"require_relative "greeter"
"#,
        )
        .file(
            "app/main.rb",
            r#"require_relative "../lib/loader"

Greeter.new.hello
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"lib/greeter.rb","line":2,"column":7}],"include_tests":true}"#,
        )
        .expect("scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!("Greeter.hello", result["symbol"], "payload: {value}");
    assert_eq!("found", result["status"], "payload: {value}");
    assert_eq!(1, result["total_hits"], "payload: {value}");
}

#[test]
fn scan_usages_by_location_matches_ruby_autoload_benchmark_case() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/shop/discount.rb",
            r#"module Shop
  class Discount
    def self.default
      new
    end
  end
end
"#,
        )
        .file(
            "lib/shop/product.rb",
            r#"module Shop
  class Product
  end

  autoload :Discount, "shop/discount"
end
"#,
        )
        .file(
            "app/catalog.rb",
            r#"require_relative "../lib/shop/product"

product = Shop::Product.new
Shop::Discount.default
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"lib/shop/discount.rb","line":2,"column":9}],"include_tests":true}"#,
        )
        .expect("scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!("Shop$Discount", result["symbol"], "payload: {value}");
    assert_eq!("found", result["status"], "payload: {value}");
    assert_eq!(2, result["total_hits"], "payload: {value}");
    let autoload = result["files"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .find(|hit| {
            hit["snippet"]
                .as_str()
                .is_some_and(|snippet| snippet.contains("autoload :Discount"))
        })
        .unwrap_or_else(|| panic!("missing autoload hit: {value}"));
    assert_eq!(autoload["column"], 13, "payload: {value}");
    assert_eq!(autoload["end_column"], 21, "payload: {value}");
}

#[test]
fn scan_usages_by_location_selector_preserves_python_module_target() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "example/service.py",
            r#"DEFAULT_PREFIX = "job"

class Repository:
    pass

class Service:
    def execute(self, name):
        return f"{DEFAULT_PREFIX}:{name}"
"#,
        )
        .file(
            "example/__init__.py",
            "from .service import DEFAULT_PREFIX, Repository, Service\n",
        )
        .file(
            "tests/test_service.py",
            "from example import DEFAULT_PREFIX\n\ndef test_prefix():\n    assert DEFAULT_PREFIX == \"job\"\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"example/service.py","line":1,"column":1,"symbol":"example.service"}],"include_tests":true}"#,
        )
        .expect("scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!("example.service", result["symbol"], "payload: {value}");
    assert_eq!("verified_absent", result["status"], "payload: {value}");
    assert_eq!(0, result["total_hits"], "payload: {value}");
}

#[test]
fn scan_usages_by_reference_requires_symbols() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    for args in [r#"{}"#, r#"{"symbols":[]}"#] {
        let err = service
            .call_tool_json("scan_usages_by_reference", args)
            .unwrap_err();
        assert_eq!(SearchToolsServiceErrorCode::InvalidParams, err.code);
        assert!(
            err.message.contains("requires a non-empty `symbols` array"),
            "unexpected error for {args}: {}",
            err.message
        );
    }
}

#[test]
fn scan_usages_by_location_validation_names_its_own_arguments() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    for args in [
        r#"{}"#,
        r#"{"targets":[]}"#,
        r#"{"targets":[{"path":"A.java"}]}"#,
        r#"{"targets":[{"path":"A.java","line":1,"symbol":"   "}]}"#,
    ] {
        let error = service
            .call_tool_json("scan_usages_by_location", args)
            .unwrap_err();
        assert_eq!(SearchToolsServiceErrorCode::InvalidParams, error.code);
        assert!(
            error.message.contains("scan_usages_by_location") && error.message.contains("target"),
            "unexpected error for {args}: {}",
            error.message
        );
        assert!(!error.message.contains("symbols"), "{}", error.message);
    }
}

#[test]
fn scan_usages_location_target_disambiguates_commonjs_declarations() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "node_modules/accepts/index.js",
            "module.exports = function accepts() {};\n",
        )
        .file(
            "lib/request.js",
            r#"
var accepts = require("accepts");

var req = exports = module.exports = {};

req.accepts = function acceptsMethod(type) {
  return accepts(this).types(type);
};
"#,
        )
        .file(
            "app.js",
            r#"
var req = require("./lib/request");

function run() {
  return req.accepts("json");
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let string_payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["accepts"],"include_tests":true}"#,
        )
        .unwrap();
    let string_value: Value = serde_json::from_str(&string_payload).unwrap();
    assert!(
        only_result(&string_value)["status"] == "ambiguous",
        "bare string selector should remain ambiguous: {string_value}"
    );

    let dependency_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"lib/request.js","line":2,"column":5}],"include_tests":true}"#,
        )
        .unwrap();
    let dependency: Value = serde_json::from_str(&dependency_payload).unwrap();
    assert_eq!(0, status_count(&dependency, "ambiguous"), "{dependency}");
    assert_eq!(0, status_count(&dependency, "failure"), "{dependency}");
    assert_eq!(
        "lib/request.js#request.js.accepts",
        only_result(&dependency)["symbol"],
        "{dependency}"
    );
    assert_eq!(1, only_result(&dependency)["total_hits"], "{dependency}");
    assert_eq!(
        "lib/request.js",
        only_result(&dependency)["files"][0]["path"],
        "{dependency}"
    );
    assert_eq!(
        "req.accepts",
        only_result(&dependency)["files"][0]["hits"][0]["enclosing"],
        "{dependency}"
    );

    let method_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"lib/request.js","line":6,"column":5}],"include_tests":true}"#,
        )
        .unwrap();
    let method: Value = serde_json::from_str(&method_payload).unwrap();
    // The seedless candidate scan resolves the anchored method target and
    // surfaces the cross-file callsite as unproven (receiver proof for the
    // CommonJS namespace object is incomplete).
    assert_eq!(0, status_count(&method, "ambiguous"), "{method}");
    assert_eq!(0, status_count(&method, "failure"), "{method}");
    assert_eq!(
        "lib/request.js#req.accepts",
        only_result(&method)["symbol"],
        "{method}"
    );
    assert_eq!(0, only_result(&method)["total_hits"], "{method}");
    assert_eq!(1, only_result(&method)["unproven_hits"], "{method}");
    assert_eq!(
        "app.js",
        only_result(&method)["unproven_files"][0]["path"],
        "{method}"
    );
    assert_eq!(
        "run",
        only_result(&method)["unproven_files"][0]["hits"][0]["enclosing"],
        "{method}"
    );
}

#[test]
fn scan_usages_by_reference_resolves_javascript_namespace_export_aliases() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "fixtures.js",
            "function readFixtureKey() {}\nmodule.exports = { readKey: readFixtureKey };\n",
        )
        .file(
            "other.js",
            "function readOtherKey() {}\nmodule.exports = { readKey: readOtherKey };\n",
        )
        .file(
            "consumer.js",
            r#"
const fixtures = require("./fixtures");
const other = require("./other");

exports.run = function() {
  fixtures.readKey();
  other.readKey();
};
"#,
        )
        .file(
            "esm-fixtures.js",
            "function loadFixtureKey() {}\nexport { loadFixtureKey as loadKey };\n",
        )
        .file(
            "esm-other.js",
            "function loadOtherKey() {}\nexport { loadOtherKey as loadKey };\n",
        )
        .file(
            "esm-consumer.js",
            r#"
import * as fixtures from "./esm-fixtures.js";
import * as other from "./esm-other.js";

export function run() {
  fixtures.loadKey();
  other.loadKey();
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["readFixtureKey"],"include_tests":true,"paths":["consumer.js"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let result = only_result(&value);

    assert_eq!(result["status"], "found", "payload: {value}");
    assert_eq!(result["total_hits"], 1, "payload: {value}");
    assert_eq!(
        result["files"][0]["path"], "consumer.js",
        "payload: {value}"
    );
    assert_eq!(result["files"][0]["hits"][0]["line"], 6, "payload: {value}");
    assert_eq!(result["unproven_hits"], 0, "payload: {value}");

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["loadFixtureKey"],"include_tests":true,"paths":["esm-consumer.js"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let result = only_result(&value);

    assert_eq!(result["status"], "found", "payload: {value}");
    assert_eq!(result["total_hits"], 1, "payload: {value}");
    assert_eq!(
        result["files"][0]["path"], "esm-consumer.js",
        "payload: {value}"
    );
    assert_eq!(result["files"][0]["hits"][0]["line"], 6, "payload: {value}");
    assert_eq!(result["unproven_hits"], 0, "payload: {value}");
}

#[test]
fn scan_usages_by_reference_resolves_javascript_commonjs_export_value_roles() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "exports.js",
            r#"
function parse() {}
class ExportedClass {}
function exportedName() {}
function actualValue() {}

module.exports = parse;
exports.types = { ExportedClass };
exports.alias = { exportedName: actualValue };
exports.run = function(parse) {
  parse();
};
"#,
        )
        .file(
            "qualifier.js",
            r#"
const bench = makeBench();
const unrelated = makeBench();

exports.run = function(bench) {
  bench.start();
};
exports.measure = function() {
  bench.start();
  unrelated.start();
};
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    for (symbol, expected_line) in [("parse", 7), ("ExportedClass", 8), ("actualValue", 9)] {
        let args = serde_json::json!({
            "symbols": [symbol],
            "include_tests": true,
            "paths": ["exports.js"],
        });
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args.to_string())
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let result = only_result(&value);
        assert_eq!(result["total_hits"], 1, "payload: {value}");
        assert_eq!(
            result["files"][0]["hits"][0]["line"], expected_line,
            "payload: {value}"
        );
    }

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["exportedName"],"include_tests":true,"paths":["exports.js"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(only_result(&value)["total_hits"], 0, "payload: {value}");

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["bench"],"include_tests":true,"paths":["qualifier.js"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let result = only_result(&value);
    assert_eq!(result["total_hits"], 1, "payload: {value}");
    assert_eq!(result["files"][0]["hits"][0]["line"], 9, "payload: {value}");
    assert_eq!(result["unproven_hits"], 0, "payload: {value}");
}

#[test]
fn scan_usages_by_reference_preserves_javascript_property_alias_provenance() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "context.js",
            r#"function setupSessions() {
  const contextGroup = makeContextGroup();
  return { contextGroup };
}
function useContext() {
  const { contextGroup } = setupSessions();
  contextGroup.createContext();
  const result = setupSessions();
  const alias = result.contextGroup;
  alias.createContext();
  const unrelated = { contextGroup: makeContextGroup() };
  unrelated.contextGroup.createContext();
  function shadow(contextGroup) { contextGroup.createContext(); }
}
"#,
        )
        .file(
            "holder.js",
            r#"class Holder {
  constructor() { this.ret = makeValue(); }
  use() {
    const { ret } = this;
    ret.run();
    const alias = ret;
    alias.run();
    const unrelated = { ret: makeValue() };
    unrelated.ret.run();
    function shadow(ret) { ret.run(); }
  }
}
"#,
        )
        .file(
            "proxy.js",
            r#"function createProxyServer() {
  const proxy = makeProxy();
  return { proxy };
}
function start() {
  const returned = createProxyServer();
  const { proxy } = returned;
  proxy.listen();
  const unrelated = { proxy: makeProxy() };
  unrelated.proxy.listen();
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    for (symbol, path, expected_lines, rejected_lines) in [
        (
            "setupSessions.contextGroup",
            "context.js",
            vec![6, 7, 9, 10],
            vec![12, 13],
        ),
        ("Holder.ret", "holder.js", vec![4, 5, 7], vec![9, 10]),
        ("createProxyServer.proxy", "proxy.js", vec![7, 8], vec![10]),
    ] {
        let args = serde_json::json!({
            "symbols": [symbol],
            "include_tests": true,
            "paths": [path],
        });
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args.to_string())
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let result = only_result(&value);
        assert_eq!(result["status"], "found", "payload: {value}");
        assert_eq!(result["unproven_hits"], 0, "payload: {value}");
        let lines: BTreeSet<u64> = result["files"][0]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|hit| hit["line"].as_u64())
            .collect();
        for expected in expected_lines {
            assert!(
                lines.contains(&expected),
                "missing line {expected}: {value}"
            );
        }
        for rejected in rejected_lines {
            assert!(
                !lines.contains(&rejected),
                "unexpected line {rejected}: {value}"
            );
        }
    }
}

#[test]
fn scan_usages_location_target_uses_column_on_same_line_declarations() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            "export function first() {} export function second() {}\nfirst();\nsecond();\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app.js","line":1,"column":44}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "ambiguous"), "payload: {value}");
    assert_eq!("app.js#second", only_result(&value)["symbol"], "{value}");
}

#[test]
fn scan_usages_location_batch_follows_chained_rust_type_reexports() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            r#"[package]
name = "demo"
version = "0.1.0"
edition = "2024"
"#,
        )
        .file(
            "src/query/ir.rs",
            r#"pub struct CodeQueryPlan;
pub struct LogicalQueryPlan;
"#,
        )
        .file(
            "src/query/mod.rs",
            r#"mod ir;
pub use ir::{CodeQueryPlan, LogicalQueryPlan};
"#,
        )
        .file(
            "src/structural/mod.rs",
            r#"pub use crate::query::{CodeQueryPlan, LogicalQueryPlan};
"#,
        )
        .file(
            "src/lib.rs",
            r#"pub mod query;
pub mod structural;
pub mod execution;
"#,
        )
        .file(
            "src/execution.rs",
            r#"use crate::structural::{CodeQueryPlan, LogicalQueryPlan};

pub fn execute(plan: &CodeQueryPlan, logical: &LogicalQueryPlan) {}
"#,
        )
        .file(
            "src/main.rs",
            r#"use demo::structural::CodeQueryPlan;

fn plan_summary_text(plan: &CodeQueryPlan) {}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let args = serde_json::json!({
        "targets": [
            {"path": "src/query/ir.rs", "line": 1, "column": 12},
            {"path": "src/query/ir.rs", "line": 2, "column": 12}
        ],
        "include_tests": true
    });
    let payload = service
        .call_tool_json("scan_usages_by_location", &args.to_string())
        .expect("location scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");

    assert_eq!(2, results(&value).len(), "payload: {value}");
    for (short_name, result) in ["CodeQueryPlan", "LogicalQueryPlan"]
        .into_iter()
        .zip(results(&value))
    {
        assert_eq!("found", result["status"], "payload: {value}");
        assert_eq!(0, result["unproven_hits"], "payload: {value}");
        assert!(
            result["fq_name"]
                .as_str()
                .is_some_and(|fq_name| fq_name.ends_with(short_name)),
            "payload: {value}"
        );
        assert!(
            result["files"].as_array().is_some_and(|files| {
                files.iter().any(|file| {
                    file["path"] == "src/execution.rs"
                        && file["hits"].as_array().is_some_and(|hits| {
                            hits.iter().any(|hit| {
                                hit["snippet"]
                                    .as_str()
                                    .is_some_and(|snippet| snippet.contains(short_name))
                            })
                        })
                })
            }),
            "missing execution-layer use: {value}"
        );
    }
    let code_query = results(&value)
        .iter()
        .find(|result| {
            result["fq_name"]
                .as_str()
                .is_some_and(|fq_name| fq_name.ends_with("CodeQueryPlan"))
        })
        .expect("CodeQueryPlan result");
    assert!(
        code_query["files"].as_array().is_some_and(|files| {
            files.iter().any(|file| {
                file["path"] == "src/main.rs"
                    && file["hits"].as_array().is_some_and(|hits| {
                        hits.iter().any(|hit| {
                            hit["snippet"]
                                .as_str()
                                .is_some_and(|snippet| snippet.contains("plan_summary_text"))
                        })
                    })
            })
        }),
        "missing crate-facing re-export use: {value}"
    );
}

#[test]
fn scan_usages_location_target_selects_js_object_literal_method() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "library.js",
            "const helpers = {\n  formatTask(task) {\n    return task.label;\n  },\n  render() {\n    return helpers.formatTask(this);\n  },\n};\nexport { helpers };\n",
        )
        .file(
            "consumer.js",
            "import { helpers } from './library.js';\n\nexport function run(directTask) {\n  return helpers.formatTask(directTask);\n}\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"library.js","line":2,"column":3}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "ambiguous"), "payload: {value}");
    assert_eq!(0, status_count(&value, "failure"), "payload: {value}");
    assert_eq!(0, status_count(&value, "not_found"), "payload: {value}");
    assert_eq!(
        "library.js#library.js.helpers.formatTask",
        only_result(&value)["symbol"],
        "{value}"
    );
    assert_eq!(
        2,
        only_result(&value)["total_hits"],
        "binding-only export sites should be omitted from external usages: {value}"
    );

    let files = only_result(&value)["files"].as_array().unwrap();
    assert!(
        files.iter().any(|file| {
            file["path"] == "library.js"
                && file["hits"].as_array().unwrap().iter().any(|hit| {
                    hit["snippet"]
                        .as_str()
                        .is_some_and(|snippet| snippet.contains("helpers.formatTask(this)"))
                })
        }),
        "payload: {value}"
    );
    assert!(
        files.iter().any(|file| {
            file["path"] == "consumer.js"
                && file["hits"].as_array().unwrap().iter().any(|hit| {
                    hit["snippet"]
                        .as_str()
                        .is_some_and(|snippet| snippet.contains("helpers.formatTask(directTask)"))
                })
        }),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_location_recovers_lookup_only_local_assignment_property_reads() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "assignment.js",
            r#"function selected(other) {
  const node = {};
  consume(node.operator);
  node.operator = normalize(node.operator);
  consume(node.operator);
  node.operator = "+";
  consume(other.operator);
  {
    const node = {};
    consume(node.operator);
  }
}

function sibling() {
  const node = {};
  consume(node.operator);
}
"#,
        )
        .file(
            "other.js",
            r#"function elsewhere() {
  const node = {};
  consume(node.operator);
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"assignment.js","line":4,"column":8,"symbol":"node.operator"}],"include_tests":true}"#,
        )
        .expect("location scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!("found", result["status"], "payload: {value}");
    assert_eq!("assignment.js#node.operator", result["symbol"], "{value}");
    assert_eq!(0, result["unproven_hits"], "payload: {value}");
    assert_eq!(2, result["total_hits"], "payload: {value}");
    assert_eq!("assignment.js", result["files"][0]["path"], "{value}");
    let lines: BTreeSet<u64> = result["files"][0]["hits"]
        .as_array()
        .expect("hits array")
        .iter()
        .map(|hit| hit["line"].as_u64().expect("hit line"))
        .collect();
    assert_eq!(BTreeSet::from([4, 5]), lines, "payload: {value}");

    let unrelated_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"assignment.js","line":7,"column":17,"symbol":"node.operator"}],"include_tests":true}"#,
        )
        .expect("unrelated location scan succeeds");
    let unrelated: Value = serde_json::from_str(&unrelated_payload).expect("valid response");
    assert_eq!(
        "not_found",
        only_result(&unrelated)["status"],
        "{unrelated}"
    );
}

#[test]
fn scan_usages_location_recovers_nested_local_assignment_property_reads() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "fetch.js",
            r#"function selected(fetchParams, other) {
  consume(fetchParams.controller.controller);
  const stream = {
    start(controller) {
      fetchParams.controller.controller = controller;
      consume(fetchParams.controller.controller);
    },
  };
  consume(fetchParams.controller.controller);
  consume(other.controller.controller);
  consume(fetchParams.other.controller);
  {
    const fetchParams = {};
    consume(fetchParams.controller.controller);
  }
  return stream;
}

function sibling(fetchParams) {
  consume(fetchParams.controller.controller);
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"fetch.js","line":5,"column":30,"symbol":"fetchParams.controller.controller"}],"include_tests":true}"#,
        )
        .expect("location scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!("found", result["status"], "payload: {value}");
    assert_eq!(
        "fetch.js#fetchParams.controller.controller", result["symbol"],
        "{value}"
    );
    assert_eq!(0, result["unproven_hits"], "payload: {value}");
    assert_eq!(2, result["total_hits"], "payload: {value}");
    let lines: BTreeSet<u64> = result["files"][0]["hits"]
        .as_array()
        .expect("hits array")
        .iter()
        .map(|hit| hit["line"].as_u64().expect("hit line"))
        .collect();
    assert_eq!(BTreeSet::from([6, 9]), lines, "payload: {value}");
}

#[test]
fn scan_usages_location_recovers_lookup_only_local_object_property_reads() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "object.js",
            r#"consume(options.enabled);
export const options = { enabled: true };
consume(options.enabled);
options.enabled = false;
consume(other.enabled);

function shadowed() {
  const options = {};
  consume(options.enabled);
}

function sibling() {
  const options = {};
  consume(options.enabled);
}
"#,
        )
        .file(
            "other.js",
            r#"function elsewhere() {
  const options = {};
  consume(options.enabled);
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"object.js","line":2,"column":26,"symbol":"options.enabled"}],"include_tests":true}"#,
        )
        .expect("location scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!("found", result["status"], "payload: {value}");
    assert_eq!("object.js#options.enabled", result["symbol"], "{value}");
    assert_eq!(0, result["unproven_hits"], "payload: {value}");
    assert_eq!(1, result["total_hits"], "payload: {value}");
    assert_eq!("object.js", result["files"][0]["path"], "{value}");
    assert_eq!(3, result["files"][0]["hits"][0]["line"], "{value}");
}

#[test]
fn scan_usages_location_recovers_declared_commonjs_export_root_property_reads() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "safer.js",
            r#"var plain = {};
plain.kStringMaxLength = 1;
consume(plain.kStringMaxLength);

var safer = {};
if (!safer.kStringMaxLength) {
  safer.kStringMaxLength = getLimit();
}
if (!safer.constants) {
  safer.constants = {};
  if (safer.kStringMaxLength) {
    safer.constants.MAX_STRING_LENGTH = safer.kStringMaxLength;
  }
}
consume(other.kStringMaxLength);
{
  const safer = {};
  consume(safer.kStringMaxLength);
}

function sibling() {
  const safer = {};
  consume(safer.kStringMaxLength);
}

module.exports = safer;
"#,
        )
        .file(
            "consumer.js",
            r#"const exported = require("./safer");
consume(exported.kStringMaxLength);
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"safer.js","line":7,"column":9,"symbol":"safer.kStringMaxLength"}],"include_tests":true}"#,
        )
        .expect("location scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!("found", result["status"], "payload: {value}");
    assert_eq!(
        "safer.js#safer.kStringMaxLength", result["symbol"],
        "{value}"
    );
    assert_eq!(0, result["unproven_hits"], "payload: {value}");
    assert_eq!(3, result["total_hits"], "payload: {value}");
    let hits: BTreeSet<(String, u64)> = result["files"]
        .as_array()
        .expect("files array")
        .iter()
        .flat_map(|file| {
            let path = file["path"].as_str().expect("file path").to_string();
            file["hits"]
                .as_array()
                .expect("hits array")
                .iter()
                .map(move |hit| (path.clone(), hit["line"].as_u64().expect("hit line")))
        })
        .collect();
    assert_eq!(
        BTreeSet::from([
            ("consumer.js".to_string(), 2),
            ("safer.js".to_string(), 11),
            ("safer.js".to_string(), 12),
        ]),
        hits,
        "payload: {value}"
    );
}

#[test]
fn scan_usages_location_prefers_scala_class_over_shared_primary_constructor_range() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Service.scala",
            r#"package app

class Service(value: String)

object Factory {
  val first = new Service("first")
  val second = new Service("second")
  val third = new Service("third")
}
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app/Service.scala","line":3,"column":7}],"include_tests":true}"#,
        )
        .expect("class location scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let class = only_result(&value);
    assert_eq!("found", class["status"], "payload: {value}");
    assert_eq!("app.Service", class["symbol"], "payload: {value}");
    assert_eq!(Some(3), class["total_hits"].as_u64(), "payload: {value}");

    let anchored_class_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app/Service.scala","line":3,"column":7,"symbol":"app/Service.scala#app.Service"}],"include_tests":true}"#,
        )
        .expect("file-anchored class location scan succeeds");
    let anchored_class_value: Value =
        serde_json::from_str(&anchored_class_payload).expect("valid response");
    let anchored_class = only_result(&anchored_class_value);
    assert_eq!(
        "found", anchored_class["status"],
        "payload: {anchored_class_value}"
    );
    assert_eq!(
        "app.Service", anchored_class["symbol"],
        "payload: {anchored_class_value}"
    );
    assert_eq!(
        Some(3),
        anchored_class["total_hits"].as_u64(),
        "payload: {anchored_class_value}"
    );

    let constructor_payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app/Service.scala","line":3,"column":7,"symbol":"app.Service.Service"}],"include_tests":true}"#,
        )
        .expect("constructor location scan succeeds");
    let constructor_value: Value =
        serde_json::from_str(&constructor_payload).expect("valid response");
    let constructor = only_result(&constructor_value);
    assert_eq!(
        "found", constructor["status"],
        "payload: {constructor_value}"
    );
    assert_eq!(
        "app.Service.Service", constructor["symbol"],
        "payload: {constructor_value}"
    );
    assert_eq!(
        Some(3),
        constructor["total_hits"].as_u64(),
        "payload: {constructor_value}"
    );
}

#[test]
fn scan_usages_location_target_selects_typescript_static_method() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/api.ts",
            r#"export class ApiClient {
  static create(baseUrl: string): ApiClient {
    return new ApiClient(baseUrl);
  }

  create(): void {}

  constructor(private readonly baseUrl: string) {}
}

export default function createClient(): ApiClient {
  return ApiClient.create("/api");
}
"#,
        )
        .file(
            "src/app.ts",
            r#"import { ApiClient } from "./api";

const direct = ApiClient.create("/direct");
"#,
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"src/api.ts","line":2,"column":10,"symbol":"ApiClient.create"}],"include_tests":true}"#,
        )
        .expect("scan succeeds");
    let value: Value = serde_json::from_str(&payload).expect("valid response");
    let result = only_result(&value);

    assert_eq!(
        "src/api.ts#ApiClient.create$static", result["symbol"],
        "payload: {value}"
    );
    assert_eq!("found", result["status"], "payload: {value}");
    assert_eq!(2, result["total_hits"], "payload: {value}");
    assert!(
        result["files"].as_array().is_some_and(|files| {
            files.iter().any(|file| {
                file["path"] == "src/api.ts"
                    && file["hits"]
                        .as_array()
                        .is_some_and(|hits| hits.iter().any(|hit| hit["line"] == 12))
            }) && files.iter().any(|file| {
                file["path"] == "src/app.ts"
                    && file["hits"]
                        .as_array()
                        .is_some_and(|hits| hits.iter().any(|hit| hit["line"] == 3))
            })
        }),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_location_accepts_scala_display_selectors_for_object_members() {
    let source = r#"package example

object Defaults {
  val Prefix = "job"
}

object Service {
  def build: String = Defaults.Prefix
}

class ConsoleRenderer
object ConsoleRenderer {
  def default: ConsoleRenderer = new ConsoleRenderer
}

object Syntax {
  extension (value: String)
    def slug: String = value.toLowerCase
}

object App {
  import ConsoleRenderer.{default => renderer}
  import Syntax.*
  val service = Service.build
  val prefix = Defaults.Prefix
  val console = renderer
  val second = renderer
  val slugged = "Hello World".slug
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("example/Workflow.scala", source)
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    for (selector, declaration_line, expected_hits) in [
        ("example.Service.build", line_of(source, "def build"), 1),
        ("example.Defaults.Prefix", line_of(source, "val Prefix"), 2),
        (
            "example.ConsoleRenderer.default",
            line_of(source, "def default"),
            2,
        ),
        ("example.Syntax.slug", line_of(source, "def slug"), 1),
    ] {
        let args = serde_json::json!({
            "targets": [{
                "path": "example/Workflow.scala",
                "line": declaration_line,
                "symbol": selector,
            }],
            "include_tests": true,
        });
        let payload = service
            .call_tool_json("scan_usages_by_location", &args.to_string())
            .expect("Scala location scan succeeds");
        let value: Value = serde_json::from_str(&payload).expect("valid response");
        let result = only_result(&value);

        assert_eq!("found", result["status"], "selector {selector}: {value}");
        assert_eq!(
            expected_hits, result["total_hits"],
            "selector {selector}: {value}"
        );
    }
}

#[test]
fn scan_usages_location_target_does_not_select_nested_same_line_member() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            "export class Widget { render() {} }\nnew Widget();\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app.js","line":1,"column":14}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "ambiguous"), "payload: {value}");
    assert_eq!("app.js#Widget", only_result(&value)["symbol"]);
}

#[test]
fn scan_usages_by_reference_ambiguity_uses_symbolic_candidates_only() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("a.js", "export function helper() {}\n")
        .file("b.js", "export function helper() {}\n")
        .file("c.js", "export function helper() {}\n")
        .file("d.js", "export function helper() {}\n")
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["helper"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let ambiguous = only_result(&value);

    assert_eq!(4, ambiguous["candidate_targets"].as_array().unwrap().len());
    assert!(ambiguous["candidate_details"].is_null());
    assert!(ambiguous["candidate_details_total"].is_null());
    assert!(ambiguous["candidate_details_truncated"].is_null());
    assert!(
        !ambiguous["message"].as_str().unwrap().contains("location"),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_by_reference_ambiguous_candidates_round_trip_across_languages() {
    let project = InlineTestProject::new()
        .file(
            "api.php",
            "<?php\nfunction get_string($value) { return $value; }\nget_string('php');\n",
        )
        .file(
            "api.js",
            "export function get_string(value) { return value; }\nget_string('js');\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["get_string"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let ambiguous = only_result(&value);
    assert_eq!(ambiguous["status"], "ambiguous", "payload: {value}");
    let candidates = ambiguous["candidate_targets"].as_array().unwrap();
    assert_eq!(candidates.len(), 2, "payload: {value}");

    let selectors: std::collections::BTreeSet<_> = candidates
        .iter()
        .map(|candidate| candidate.as_str().unwrap())
        .collect();
    assert_eq!(selectors.len(), candidates.len(), "payload: {value}");
    for selector in selectors {
        assert!(
            selector.contains('#'),
            "selector must be unique: {selector}"
        );
        assert_ne!(selector, "get_string");
        let args = serde_json::json!({
            "symbols": [selector],
            "include_tests": true,
        });
        let retry_payload = service
            .call_tool_json("scan_usages_by_reference", &args.to_string())
            .unwrap();
        let retry: Value = serde_json::from_str(&retry_payload).unwrap();
        let result = only_result(&retry);
        assert_eq!(result["status"], "found", "payload: {retry}");
        assert_eq!(result["total_hits"], 1, "payload: {retry}");
    }
}

#[test]
fn scan_usages_location_rejects_arbitrary_body_lines() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            "export function run() {\n  const value = 1;\n  return value;\n}\nrun();\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app.js","line":2}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, status_count(&value, "not_found"), "payload: {value}");
    let message = only_result(&value)["message"]
        .as_str()
        .expect("not-found message");
    assert!(message.contains("no declaration at location"), "{message}");
    assert!(
        message.contains("Requested location: app.js:2 (column not supplied)"),
        "{message}"
    );
    assert!(message.contains("  1 | export function run()"), "{message}");
    assert!(message.contains("> 2 |   const value = 1;"), "{message}");
    assert!(message.contains("  3 |   return value;"), "{message}");
    assert!(
        message.contains("^ requested line 2; column not supplied"),
        "{message}"
    );
    assert!(message.contains("Recovery:"), "{message}");
    assert!(message.contains("declaration name token"), "{message}");
    assert!(message.contains("search_symbols"), "{message}");
}

#[test]
fn scan_usages_invalid_line_includes_nearest_source_boundary() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", "const value = 1;\nvalue;\n")
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app.js","line":9,"column":3}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let result = only_result(&value);
    let message = result["message"].as_str().expect("failure message");

    assert_eq!("failure", result["status"], "payload: {value}");
    assert!(
        message.contains("Requested location: app.js:9:3"),
        "{message}"
    );
    assert!(message.contains("  2 | value;"), "{message}");
    assert!(
        message.contains("> 9 | [requested line is after the last source line]"),
        "{message}"
    );
    assert!(
        message.contains("^ requested line 9, column 3"),
        "{message}"
    );
}

#[test]
fn scan_usages_location_never_selects_a_declaration_from_another_file() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/First.java",
            "package sample;\nclass Duplicate {\n  void local() {}\n}\n",
        )
        .file(
            "src/Second.java",
            "package sample;\nclass Duplicate {\n  void wrong() {}\n}\n",
        )
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"src/First.java","line":3,"column":8}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let result = only_result(&value);

    assert_eq!(
        "sample.Duplicate.local", result["symbol"],
        "payload: {value}"
    );
    assert!(
        result["definition_path"] == "src/First.java",
        "payload: {value}"
    );
}

#[test]
fn scan_usages_location_columns_count_unicode_characters() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", "export function café() {}\ncafé();\n")
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("service");

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"app.js","line":1,"column":20}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(
        "app.js#café",
        only_result(&value)["symbol"],
        "payload: {value}"
    );
}

#[test]
fn scan_usages_reports_unknown_symbol_as_not_found() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["does.not.Exist"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, resolved_scan_count(&value));
    let not_found = only_result(&value);
    assert_eq!("not_found", not_found["status"]);
    assert_eq!("does.not.Exist", not_found["input"]);
    assert!(
        not_found["message"]
            .as_str()
            .is_some_and(|message| message.contains("no symbol matched"))
    );
    assert_eq!(0, status_count(&value, "failure"));
}

#[test]
fn scan_usages_multi_symbol_rendered_banner_names_not_found_member() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Target.java",
            "public class Target {\n    public void hit() {}\n}\n",
        )
        .file(
            "Caller.java",
            "public class Caller {\n    public void run() { new Target().hit(); }\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_payload_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Target.hit","Target.missing"],"include_tests":true}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let structured = &value["structured"];
    assert_eq!(2, structured["summary"]["requested"]);
    assert_eq!(1, structured["summary"]["found"]);
    assert_eq!(1, structured["summary"]["not_found"]);
    assert_eq!(0, structured["summary"]["failure"]);

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.starts_with(
            "2 scan_usages_by_reference requests: 1 found; 1 not_found; see per-request sections.\nNot found: Target.missing."
        ),
        "{rendered}"
    );
}

#[test]
fn scan_usages_reports_unproven_sites_instead_of_unsafe_inference_failure() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("Domain")).unwrap();
    fs::write(
        temp.path().join("Domain").join("Target.cs"),
        r#"
namespace Domain {
    public class Target {
        public void Run() {}
    }
}
"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("Domain").join("Consumer.cs"),
        r#"
namespace Domain {
    public class Consumer {
        public void Execute(dynamic value) {
            value.Run();
        }
    }
}
"#,
    )
    .unwrap();
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Domain.Target.Run"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, status_count(&value, "failure"), "payload: {value}");
    assert_eq!(0, status_count(&value, "not_found"));
    let usage = only_result(&value);
    assert_eq!("Domain.Target.Run", usage["symbol"]);
    assert_eq!(0, usage["total_hits"], "payload: {value}");
    assert_eq!(1, usage["unproven_hits"], "payload: {value}");
    assert!(
        usage["unproven_files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()),
        "unproven sites must be rendered: {value}"
    );
    assert!(
        usage["status"] == "unverified_absent",
        "unproven evidence must block the verified-absent claim: {value}"
    );
    let hit = &usage["unproven_files"][0]["hits"][0];
    assert_eq!(5, hit["line"], "payload: {value}");
    assert!(hit["column"].as_u64().is_some(), "payload: {value}");
    assert_eq!(hit["line"], hit["end_line"], "payload: {value}");
    assert!(
        hit["end_column"].as_u64().unwrap() > hit["column"].as_u64().unwrap(),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_by_reference_rejects_blank_symbols() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let error = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["", "   ", "E.iMethod"],"include_tests":true}"#,
        )
        .unwrap_err();

    assert_eq!(SearchToolsServiceErrorCode::InvalidParams, error.code);
    assert!(error.message.contains("scan_usages_by_reference"));
    assert!(error.message.contains("non-blank"));
}

#[test]
fn scan_usages_excludes_test_files_when_include_tests_is_false() {
    // Three callers of `Greeter.hello`: one in production code, one in a JUnit
    // test file, and one helper under a test root with no runnable test marker.
    // With include_tests=false, both test-surface callers must be filtered
    // before the regex scan so that test hits do not eat into DEFAULT_MAX_USAGES
    // and do not appear in the result. With include_tests=true, all callers must
    // show up.
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Greeter.java"),
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("ProdCaller.java"),
        "public class ProdCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("GreeterTest.java"),
        "import org.junit.Test;\npublic class GreeterTest {\n    @Test\n    public void greets() { new Greeter().hello(); }\n}\n",
    )
    .unwrap();
    fs::create_dir_all(temp.path().join("src/test/java")).unwrap();
    fs::write(
        temp.path().join("src/test/java/GreeterFixture.java"),
        "public class GreeterFixture {\n    public String call() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let production_only = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.hello"],"include_tests":false}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&production_only).unwrap();
    let usage = only_result(&value);
    let files = usage["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"ProdCaller.java"),
        "ProdCaller.java should be in results: {value}"
    );
    assert!(
        !paths.contains(&"GreeterTest.java"),
        "GreeterTest.java must be filtered when include_tests=false: {value}"
    );
    assert!(
        !paths.contains(&"src/test/java/GreeterFixture.java"),
        "GreeterFixture.java must be filtered when include_tests=false: {value}"
    );

    let with_tests = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.hello"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&with_tests).unwrap();
    let files = only_result(&value)["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"ProdCaller.java"),
        "ProdCaller.java missing with include_tests=true: {value}"
    );
    assert!(
        paths.contains(&"GreeterTest.java"),
        "GreeterTest.java missing with include_tests=true: {value}"
    );
    assert!(
        paths.contains(&"src/test/java/GreeterFixture.java"),
        "GreeterFixture.java missing with include_tests=true: {value}"
    );
}

#[test]
fn scan_usages_paths_filter_limits_candidate_files() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("nested")).unwrap();
    fs::write(
        temp.path().join("Greeter.java"),
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("ProdCaller.java"),
        "public class ProdCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("nested").join("NestedCaller.java"),
        "public class NestedCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.hello"],"include_tests":true,"paths":["nested/*.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = only_result(&value)["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(vec!["nested/NestedCaller.java"], paths, "payload: {value}");
}

#[test]
fn scan_usages_paths_scope_is_independent_of_out_of_scope_callers() {
    // `Helper` is a high-fan-in symbol: 50+ files call it. Scoping the query to one file must
    // return only that file's call site, and the cost must not scale with how many other files
    // reference the symbol — the search is bounded by `paths`, not by the symbol's popularity.
    // This is the regression guard for the perf fix: candidates are resolved straight from
    // `paths` rather than enumerated workspace-wide and filtered after the fact.
    let mut project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "helper.go",
            "package app\n\nfunc Helper() string { return \"hi\" }\n",
        )
        .file(
            "want_caller.go",
            "package app\n\nfunc UseHere() string { return Helper() }\n",
        );
    for idx in 0..50 {
        project = project.file(
            format!("decoy{idx}.go"),
            format!("package app\n\nfunc Decoy{idx}() string {{ return Helper() }}\n"),
        );
    }
    let project = project.build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Helper"],"include_tests":true,"paths":["want_caller.go"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = only_result(&value)["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(vec!["want_caller.go"], paths, "payload: {value}");
    assert_eq!(
        1,
        only_result(&value)["total_hits"].as_u64().unwrap(),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_paths_scope_returns_all_in_scope_callers() {
    // A glob `paths` matching several files must return every in-scope call site (not just the
    // first) while still excluding out-of-scope callers.
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Greeter.java",
            "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
        )
        .file(
            "scoped/CallerA.java",
            "public class CallerA {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .file(
            "scoped/CallerB.java",
            "public class CallerB {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .file(
            "OutOfScope.java",
            "public class OutOfScope {\n    public String run() { return new Greeter().hello(); }\n}\n",
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.hello"],"include_tests":true,"paths":["scoped/*.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = only_result(&value)["files"].as_array().unwrap();
    let mut paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    paths.sort();
    assert_eq!(
        vec!["scoped/CallerA.java", "scoped/CallerB.java"],
        paths,
        "payload: {value}"
    );
}

#[test]
fn scan_usages_paths_scope_blocks_js_ts_importer_expansion() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("lib.ts", "export function helper() { return 1; }\n")
        .file(
            "scoped.ts",
            "import { helper } from './lib';\nexport const value = 1;\n",
        )
        .file(
            "out_of_scope.ts",
            "import { helper } from './lib';\nexport const value = helper();\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["helper"],"include_tests":true,"paths":["scoped.ts"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
    assert_eq!(0, only_result(&value)["total_hits"].as_u64().unwrap());
    assert!(only_result(&value)["files"].is_null(), "payload: {value}");
}

#[test]
fn scan_usages_paths_scope_blocks_csharp_target_source_leakage() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Service.cs",
            "namespace App; public class Service { public void Run() {} public void Call() { this.Run(); } }\n",
        )
        .file(
            "Scoped.cs",
            "namespace App; public class Scoped { public void Other() {} }\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["App.Service.Run"],"include_tests":true,"paths":["Scoped.cs"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
    assert_eq!(0, only_result(&value)["total_hits"].as_u64().unwrap());
}

#[test]
fn scan_usages_paths_scope_blocks_jvm_php_scala_target_source_leakage() {
    let java_project = InlineTestProject::with_language(Language::Java)
        .file(
            "Service.java",
            "public class Service { public void run() {} public void call() { run(); } }\n",
        )
        .file("Scoped.java", "public class Scoped {}\n")
        .build();
    let java_service =
        SearchToolsService::new_without_semantic_index(java_project.root().to_path_buf()).unwrap();
    let java_payload = java_service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Service.run"],"include_tests":true,"paths":["Scoped.java"]}"#,
        )
        .unwrap();
    let java_value: Value = serde_json::from_str(&java_payload).unwrap();
    assert_eq!(
        0,
        only_result(&java_value)["total_hits"].as_u64().unwrap(),
        "payload: {java_value}"
    );

    let php_project = InlineTestProject::with_language(Language::Php)
        .file(
            "Service.php",
            "<?php\nclass Service { public function run() {} public function call() { $this->run(); } }\n",
        )
        .file("Scoped.php", "<?php\nclass Scoped {}\n")
        .build();
    let php_service =
        SearchToolsService::new_without_semantic_index(php_project.root().to_path_buf()).unwrap();
    let php_payload = php_service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Service.run"],"include_tests":true,"paths":["Scoped.php"]}"#,
        )
        .unwrap();
    let php_value: Value = serde_json::from_str(&php_payload).unwrap();
    assert_eq!(
        0,
        only_result(&php_value)["total_hits"].as_u64().unwrap(),
        "payload: {php_value}"
    );

    let scala_project = InlineTestProject::with_language(Language::Scala)
        .file(
            "Service.scala",
            "class Service { def run(): Unit = {}; def call(): Unit = run() }\n",
        )
        .file("Scoped.scala", "class Scoped {}\n")
        .build();
    let scala_service =
        SearchToolsService::new_without_semantic_index(scala_project.root().to_path_buf()).unwrap();
    let scala_payload = scala_service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Service.run"],"include_tests":true,"paths":["Scoped.scala"]}"#,
        )
        .unwrap();
    let scala_value: Value = serde_json::from_str(&scala_payload).unwrap();
    assert_eq!(
        0,
        only_result(&scala_value)["total_hits"].as_u64().unwrap(),
        "payload: {scala_value}"
    );
}

#[test]
fn scan_usages_php_scoped_paths_use_workspace_hierarchy_proof() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "Contracts.php",
            r#"<?php
namespace App\Contracts;
trait JoinTrait {
    public function add_joins(array $joins): void {}
}
"#,
        )
        .file(
            "FormBase.php",
            r#"<?php
namespace App\Forms;
class BaseForm { public function display(): void {} }
"#,
        )
        .file(
            "FactoryBase.php",
            r#"<?php
namespace App\Factory;
class BaseFactory { public static function create(): void {} }
"#,
        )
        .file(
            "ServiceBases.php",
            r#"<?php
namespace App\Service;
class BaseService { public function __construct() {} }
class OtherBase { public function __construct() {} }
"#,
        )
        .file(
            "TraitRelations.php",
            r#"<?php
namespace App\Model;
use App\Contracts\JoinTrait;
class ReportColumn { use JoinTrait; }
class OtherColumn { public function add_joins(array $joins): void {} }
"#,
        )
        .file(
            "FormRelations.php",
            r#"<?php
namespace App\Forms;
class ChildForm extends BaseForm {}
class OtherForm { public function display(): void {} }
"#,
        )
        .file(
            "FactoryRelations.php",
            r#"<?php
namespace App\Factory;
class ChildFactory extends BaseFactory {}
class OtherFactory { public static function create(): void {} }
"#,
        )
        .file(
            "Caller.php",
            r#"<?php
namespace App;
use App\Model\ReportColumn;
use App\Model\OtherColumn;
use App\Forms\ChildForm;
use App\Forms\OtherForm;
use App\Factory\ChildFactory;
use App\Factory\OtherFactory;

$column = new ReportColumn();
$column->add_joins([]);
$otherColumn = new OtherColumn();
$otherColumn->add_joins([]);

$form = new ChildForm();
$form->display();
$otherForm = new OtherForm();
$otherForm->display();

ChildFactory::create();
OtherFactory::create();
"#,
        )
        .file(
            "ParentCalls.php",
            r#"<?php
namespace App\Service;
class ChildService extends BaseService {
    public function __construct() { parent::__construct(); }
}
class OtherChild extends OtherBase {
    public function __construct() { parent::__construct(); }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, path, expected) in [
        (
            "App.Contracts.JoinTrait.add_joins",
            "Caller.php",
            "$column->add_joins([])",
        ),
        (
            "App.Forms.BaseForm.display",
            "Caller.php",
            "$form->display()",
        ),
        (
            "App.Factory.BaseFactory.create",
            "Caller.php",
            "ChildFactory::create()",
        ),
        (
            "App.Service.BaseService.__construct",
            "ParentCalls.php",
            "App.Service.ChildService.__construct",
        ),
    ] {
        let args = serde_json::json!({
            "symbols": [symbol],
            "include_tests": true,
            "paths": [path],
        });
        let payload = service
            .call_tool_json("scan_usages_by_reference", &args.to_string())
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        let result = only_result(&value);

        assert_eq!(result["status"], "found", "payload: {value}");
        assert_eq!(result["total_hits"], 1, "payload: {value}");
        assert!(payload.contains(expected), "payload: {value}");
    }
}

#[test]
fn scan_usages_paths_scope_blocks_rust_empty_scope_fallback() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn target() {}\n")
        .file(
            "caller.rs",
            "use crate::target;\npub fn call() { target(); }\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["target"],"include_tests":true,"paths":["missing.rs"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
    assert_eq!(0, only_result(&value)["total_hits"].as_u64().unwrap());
}

#[test]
fn scan_usages_by_location_exposes_rust_self_type_references() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"pub struct Service { value: usize }

impl Service {
    fn new() -> Self {
        Self { value: 0 }
    }

    fn read(&self) -> usize {
        self.value
    }
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_location",
            r#"{"targets":[{"path":"lib.rs","line":1,"column":12}],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let usage = only_result(&value);

    assert_eq!("found", usage["status"], "payload: {value}");
    assert_eq!(3, usage["total_hits"], "payload: {value}");
    let hits = usage["files"][0]["hits"].as_array().unwrap();
    let lines: Vec<_> = hits
        .iter()
        .map(|hit| hit["line"].as_u64().unwrap())
        .collect();
    assert_eq!(vec![3, 4, 5], lines, "payload: {value}");
}

#[test]
fn scan_usages_by_reference_finds_exact_rust_module_path_segment() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub mod desired;

pub mod unrelated {
    pub mod desired {
        pub struct Decoy;
    }
}

pub fn consume() {
    let _: crate::desired::Thing;
    let _: crate::unrelated::desired::Decoy;
}
"#,
        )
        .file("desired.rs", "pub struct Thing;\n")
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["desired"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
    let usage = only_result(&value);
    assert_eq!(1, usage["total_hits"].as_u64().unwrap(), "payload: {value}");
    let files = usage["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("lib.rs", files[0]["path"], "payload: {value}");
    let hits = files[0]["hits"].as_array().unwrap();
    assert_eq!(1, hits.len(), "payload: {value}");
    assert_eq!(11, hits[0]["line"], "payload: {value}");
}

#[test]
fn scan_usages_by_reference_finds_owner_exact_rust_struct_field_labels() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub struct Wanted { pub same: usize, pub only: usize }
pub struct Decoy { pub same: usize, pub only: usize }

pub fn consume(same: usize, only: usize, wanted: Wanted, decoy: Decoy) {
    let _ = Wanted { same: 1, only };
    let Wanted { same: renamed, only } = wanted;
    let _ = Decoy { same: 2, only };
    let Decoy { same: renamed_decoy, only: only_decoy } = decoy;
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for symbol in ["Wanted.same", "Wanted.only"] {
        let payload = service
            .call_tool_json(
                "scan_usages_by_reference",
                &format!(r#"{{"symbols":["{symbol}"],"include_tests":true}}"#),
            )
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
        assert_eq!(
            2,
            only_result(&value)["total_hits"].as_u64().unwrap(),
            "payload: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_finds_exact_typescript_jsx_props() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "child.tsx",
            r#"
export interface ChildProps { title: string }
export interface OtherProps { title: string }
export function Child(_props: ChildProps) { return null }
export function Other(_props: OtherProps) { return null }
"#,
        )
        .file(
            "view.tsx",
            r#"
import { Child, Other } from './child'
export function ViewOne() { return <Child title="one" /> }
export function ViewTwo() { return <Child title="two" /> }
export function OtherView() { return <Other title="other" /> }
export function ExternalView() { return <External title="external" /> }
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["ChildProps.title"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
    let usage = only_result(&value);
    assert_eq!(2, usage["total_hits"].as_u64().unwrap(), "payload: {value}");
    let files = usage["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("view.tsx", files[0]["path"], "payload: {value}");
    assert_eq!(
        2,
        files[0]["hits"].as_array().unwrap().len(),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_by_reference_proves_structured_rust_instance_receivers() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub struct Wanted { pub field: usize }
impl Wanted { pub fn method(&self) {} }

pub struct Decoy { pub field: usize }
impl Decoy { pub fn method(&self) {} }

pub struct Holder { pub wanted: Wanted }
pub fn make_wanted() -> Wanted { todo!() }

pub fn consume(wanted: &Wanted, decoy: &Decoy, holder: &Holder) {
    wanted.method();
    let _ = wanted.field;

    let typed: Wanted = make_wanted();
    typed.method();
    let _ = typed.field;

    holder.wanted.method();
    let _ = holder.wanted.field;

    make_wanted().method();
    let _ = make_wanted().field;

    decoy.method();
    let _ = decoy.field;
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for symbol in ["Wanted.method", "Wanted.field"] {
        let payload = service
            .call_tool_json(
                "scan_usages_by_reference",
                &format!(r#"{{"symbols":["{symbol}"],"include_tests":true}}"#),
            )
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
        assert_eq!(
            4,
            only_result(&value)["total_hits"].as_u64().unwrap(),
            "payload: {value}"
        );
        assert_eq!(
            0,
            only_result(&value)["unproven_hits"].as_u64().unwrap(),
            "payload: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_proves_requested_rust_trait_impl_receiver() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub struct MarzanoQueryContext;

pub trait ExecContext<Q> {
    fn language(&self) -> usize;
}

pub struct MarzanoContext<'a> { marker: &'a str }
impl<'a> ExecContext<MarzanoQueryContext> for MarzanoContext<'a> {
    fn language(&self) -> usize { self.marker.len() }
}

pub struct DecoyContext;
impl ExecContext<MarzanoQueryContext> for DecoyContext {
    fn language(&self) -> usize { 0 }
}

pub fn consume<'a>(context: &'a MarzanoContext<'a>, decoy: &DecoyContext) {
    let _ = context.language();
    let _ = decoy.language();
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, expected_hits) in [("MarzanoContext.language", 1), ("ExecContext.language", 2)] {
        let payload = service
            .call_tool_json(
                "scan_usages_by_reference",
                &format!(r#"{{"symbols":["{symbol}"],"include_tests":true}}"#),
            )
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
        assert_eq!(
            expected_hits,
            only_result(&value)["total_hits"].as_u64().unwrap(),
            "payload: {value}"
        );
        assert_eq!(
            0,
            only_result(&value)["unproven_hits"].as_u64().unwrap(),
            "payload: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_finds_exact_rust_scoped_members_inside_macros() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub enum Wanted { Ready }
impl Wanted {
    pub type Assoc = usize;
    pub fn make() -> Self { Self::Ready }
}

pub enum Decoy { Ready }
impl Decoy {
    pub type Assoc = usize;
    pub fn make() -> Self { Self::Ready }
}

use Wanted::Ready;

pub fn consume(value: Wanted) {
    let _: Wanted::Assoc;
    Wanted::make();
    let _ = Wanted::Ready;
    let _ = matches!(value, Wanted::Ready);
    let _ = matches!(value, crate::Wanted::Ready);
    bail!(Wanted::make());
    bail!(crate::Wanted::make());

    let _: Decoy::Assoc;
    Decoy::make();
    let _ = Decoy::Ready;
    let _ = matches!(Decoy::Ready, crate::Decoy::Ready);
    bail!(crate::Decoy::make());
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    for (symbol, expected_hits) in [("Wanted.Assoc", 1), ("Wanted.Ready", 4), ("Wanted.make", 3)] {
        let payload = service
            .call_tool_json(
                "scan_usages_by_reference",
                &format!(r#"{{"symbols":["{symbol}"],"include_tests":true}}"#),
            )
            .unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
        assert_eq!(
            expected_hits,
            only_result(&value)["total_hits"].as_u64().unwrap(),
            "payload: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_finds_exact_fully_qualified_rust_type_owners() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub mod core;
pub mod flags;
pub mod messenger;
pub mod tracing_bridge;
pub mod unrelated;

pub fn consume() {
    crate::tracing_bridge::OpenTelemetryTracingBridge::new();
    crate::messenger::emit::VisibilityLevels::default();
    let _ = crate::core::api::AnalysisLogLevel::Error;
    crate::flags::OutputFormat::from();

    crate::unrelated::tracing_bridge::OpenTelemetryTracingBridge::new();
    crate::unrelated::messenger::emit::VisibilityLevels::default();
    let _ = crate::unrelated::core::api::AnalysisLogLevel::Error;
    crate::unrelated::flags::OutputFormat::from();
}
"#,
        )
        .file(
            "tracing_bridge.rs",
            "pub struct OpenTelemetryTracingBridge;\n",
        )
        .file(
            "messenger.rs",
            "pub mod emit { pub struct VisibilityLevels; }\n",
        )
        .file(
            "core.rs",
            "pub mod api { pub enum AnalysisLogLevel { Error } }\n",
        )
        .file("flags.rs", "pub struct OutputFormat;\n")
        .file(
            "unrelated.rs",
            r#"
pub mod tracing_bridge { pub struct OpenTelemetryTracingBridge; }
pub mod messenger { pub mod emit { pub struct VisibilityLevels; } }
pub mod core { pub mod api { pub enum AnalysisLogLevel { Error } } }
pub mod flags { pub struct OutputFormat; }
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["tracing_bridge.OpenTelemetryTracingBridge","messenger.emit.VisibilityLevels","core.api.AnalysisLogLevel","flags.OutputFormat"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(4, resolved_scan_count(&value), "payload: {value}");
    for usage in results(&value) {
        assert_eq!(1, usage["total_hits"].as_u64().unwrap(), "payload: {value}");
        let files = usage["files"].as_array().unwrap();
        assert_eq!(1, files.len(), "payload: {value}");
        assert_eq!("lib.rs", files[0]["path"], "payload: {value}");
        assert_eq!(
            1,
            files[0]["hits"].as_array().unwrap().len(),
            "payload: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_proves_exact_rust_qualified_free_functions() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub mod consumer;
pub mod decoy;
pub mod list_index;
pub mod messenger_variant;
pub mod url;
"#,
        )
        .file(
            "src/consumer.rs",
            r#"
use crate::{decoy, list_index, url};
use crate::list_index::to_unsigned as imported_to_unsigned;
use crate::messenger_variant::create_emitter as imported_create_emitter;
use crate::url::encode as imported_encode;

pub fn consume() {
    url::encode();
    crate::messenger_variant::create_emitter();
    list_index::to_unsigned();

    decoy::encode();
    decoy::create_emitter();
    decoy::to_unsigned();
}
"#,
        )
        .file("src/url.rs", "pub fn encode() {}\n")
        .file("src/messenger_variant.rs", "pub fn create_emitter() {}\n")
        .file("src/list_index.rs", "pub fn to_unsigned() {}\n")
        .file(
            "src/decoy.rs",
            "pub fn encode() {}\npub fn create_emitter() {}\npub fn to_unsigned() {}\n",
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["url.encode","messenger_variant.create_emitter","list_index.to_unsigned"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(3, resolved_scan_count(&value), "payload: {value}");
    for usage in results(&value) {
        assert_eq!(1, usage["total_hits"].as_u64().unwrap(), "payload: {value}");
        let files = usage["files"].as_array().unwrap();
        assert_eq!(1, files.len(), "payload: {value}");
        assert_eq!("src/consumer.rs", files[0]["path"], "payload: {value}");
        assert_eq!(
            1,
            files[0]["hits"].as_array().unwrap().len(),
            "payload: {value}"
        );
    }
}

#[test]
fn scan_usages_by_reference_uses_position_aware_rust_binding_scopes() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
fn language() {}

fn unshadowed_callback() {
    takes_fn(language);
}

fn local_shadow() {
    let language = 1;
    takes_value(language);
}

fn captured_shadow() {
    let language = 1;
    let callback = || takes_value(language);
    callback();
}

fn pattern_shadow(value: Option<i32>) {
    match value {
        Some(language) => takes_value(language),
        None => {}
    }
}

fn nested_function_is_isolated() {
    let language = 1;
    fn callback() {
        takes_fn(language);
    }
    callback();
}
"#,
        )
        .build();
    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["language"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(1, resolved_scan_count(&value), "payload: {value}");
    let usage = only_result(&value);
    assert_eq!(2, usage["total_hits"].as_u64().unwrap(), "payload: {value}");
    let hits = usage["files"][0]["hits"].as_array().unwrap();
    let lines: Vec<_> = hits
        .iter()
        .map(|hit| hit["line"].as_u64().unwrap())
        .collect();
    assert_eq!(vec![5, 29], lines, "payload: {value}");

    let definitions = service
        .call_tool_json(
            "get_definitions_by_reference",
            r#"{"references":[{"symbol":"captured_shadow","context":"let callback = || takes_value(language);","target":"language"},{"symbol":"pattern_shadow","context":"takes_value(language),","target":"language"}]}"#,
        )
        .unwrap();
    let definitions: Value = serde_json::from_str(&definitions).unwrap();
    for result in definitions["results"].as_array().unwrap() {
        assert_eq!("no_definition", result["status"], "payload: {definitions}");
        assert_eq!(
            "local_binding", result["diagnostics"][0]["kind"],
            "payload: {definitions}"
        );
    }
}

#[test]
fn scan_usages_paths_scope_does_not_truncate_broad_glob_candidates_before_scanning() {
    let mut project = InlineTestProject::with_language(Language::Java).file(
        "Greeter.java",
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    );
    for idx in 0..1005 {
        let body = if idx == 1004 {
            "return new Greeter().hello();"
        } else {
            "return \"skip\";"
        };
        project = project.file(
            format!("scoped/Caller{idx:04}.java"),
            format!("public class Caller{idx:04} {{\n    public String run() {{ {body} }}\n}}\n"),
        );
    }
    let project = project.build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Greeter.hello"],"include_tests":true,"paths":["scoped/*.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(false, value["summary"]["partial"], "payload: {value}");
    assert!(
        only_result(&value)["complete"].is_null(),
        "path-scoped scans must not apply the generic pre-scan candidate cap: {value}"
    );
    assert_eq!(
        1,
        only_result(&value)["total_hits"].as_u64().unwrap(),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_paths_scope_keeps_cross_language_scala_usages_of_java_type() {
    // A Java class can be referenced from Scala, and the Java usage strategy discovers those by
    // scanning Scala files in the candidate set. A path-scoped query that names a Scala file must
    // therefore still surface the cross-language usage — the language filter on path-scoped
    // candidates keeps Scala files for a Java-class target instead of dropping them.
    let project = InlineTestProject::new()
        .file(
            "com/example/Target.java",
            "package com.example;\n\npublic class Target {\n    public void run() {}\n}\n",
        )
        .file(
            "app/ScalaConsumer.scala",
            "package app\n\nimport com.example.Target\n\nclass ScalaConsumer {\n  val annotated: Target = new Target()\n}\n",
        )
        .build();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["com.example.Target"],"include_tests":true,"paths":["app/ScalaConsumer.scala"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = only_result(&value)["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        vec!["app/ScalaConsumer.scala"],
        paths,
        "cross-language Scala->Java usage must survive path scoping; payload: {value}"
    );
}

#[test]
fn scan_usages_demotes_large_result_to_summary_within_budget() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Target.java"),
        "public class Target {\n    public void hit() {}\n}\n",
    )
    .unwrap();
    for idx in 0..350 {
        fs::write(
            temp.path().join(format!("Caller{idx}.java")),
            format!(
                "public class Caller{idx} {{\n    public void run() {{ new Target().hit(); }}\n}}\n"
            ),
        )
        .unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Target.hit"],"include_tests":true}"#,
        )
        .unwrap();
    assert!(
        payload.len() <= SCAN_USAGES_RESPONSE_BUDGET_BYTES,
        "payload should stay within scan_usages budget, got {} bytes",
        payload.len()
    );

    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(1, value["summary"]["requested"].as_u64().unwrap());
    assert_eq!(1, value["summary"]["resolved"].as_u64().unwrap());
    assert_eq!(350, value["summary"]["total_hits"].as_u64().unwrap());
    assert_eq!(
        None,
        value["summary"].get("recommended_next_call"),
        "payload: {value}"
    );
    assert_eq!(0, status_count(&value, "too_many_callsites"));
    let usage = only_result(&value);
    assert_eq!("summary", usage["rendering"]);
    assert_eq!(350, usage["total_hits"].as_u64().unwrap());
    assert!(!usage["complete"].as_bool().unwrap());
    assert_eq!(
        20,
        usage["files"].as_array().unwrap().len(),
        "payload: {value}"
    );
    assert_eq!(330, usage["files_truncated"].as_u64().unwrap());
    assert!(
        usage["notes"]
            .as_array()
            .is_some_and(|notes| notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.contains("narrower `paths`")))),
        "payload: {value}"
    );
    assert!(
        usage["top_enclosing"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_too_many_callsites_returns_incomplete_summary_with_observed_files() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Target.java"),
        "public class Target {\n    public void hit() {}\n}\n",
    )
    .unwrap();
    for idx in 0..1001 {
        fs::write(
            temp.path().join(format!("Caller{idx}.java")),
            format!(
                "public class Caller{idx} {{\n    public void run() {{ new Target().hit(); }}\n}}\n"
            ),
        )
        .unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["Target.hit"],"paths":["Caller*.java"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(
        1,
        value["summary"]["requested"].as_u64().unwrap(),
        "payload: {value}"
    );
    assert_eq!(
        1,
        value["summary"]["resolved"].as_u64().unwrap(),
        "payload: {value}"
    );
    assert_eq!(true, value["summary"]["partial"], "payload: {value}");
    assert_eq!(
        1001,
        value["summary"]["total_hits"].as_u64().unwrap(),
        "payload: {value}"
    );

    let usage = only_result(&value);
    assert_eq!("too_many_callsites", usage["status"], "payload: {value}");
    assert_eq!(
        1001,
        usage["total_callsites"].as_u64().unwrap(),
        "payload: {value}"
    );
    assert_eq!(1000, usage["limit"].as_u64().unwrap(), "payload: {value}");

    assert_eq!("summary", usage["rendering"], "payload: {value}");
    assert_eq!(
        1001,
        usage["total_hits"].as_u64().unwrap(),
        "payload: {value}"
    );
    assert!(
        usage["notes"]
            .as_array()
            .is_some_and(|notes| notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.contains("incomplete summary")
                    && note.contains("`paths` from the files list")))),
        "payload: {value}"
    );
    assert!(
        usage["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()
                && files
                    .iter()
                    .all(|file| file["path"].as_str().unwrap().starts_with("Caller")
                        && file["hit_count"].as_u64() == Some(1))),
        "payload: {value}"
    );
    assert!(
        usage["files_truncated"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_resolved_symbol_with_no_hits_is_emitted_with_zero_total() {
    // method7 lives on A.AInner.AInnerInner and has no callers in the fixture.
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["A.AInner.AInnerInner.method7"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let usage = only_result(&value);
    assert_eq!("verified_absent", usage["status"]);
    assert_eq!("A.AInner.AInnerInner.method7", usage["symbol"]);
    assert_eq!(0, usage["total_hits"].as_u64().unwrap());
    assert_eq!(0, array_len(usage, "files"));
    assert_eq!(0, status_count(&value, "not_found"));
    assert_eq!(0, status_count(&value, "failure"));
}

#[test]
fn usage_graph_python_payload_includes_rendered_summary() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json("usage_graph", r#"{}"#, RenderOptions::default())
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(value["structured"]["nodes"].as_array().is_some());
    assert!(value["structured"]["edges"].as_array().is_some());
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("nodes"), "{rendered}");
    assert!(rendered.contains("edges"), "{rendered}");
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

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&nested.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_workspace_path(&value, &repo_root);
}

#[test]
fn service_initializes_generated_large_workspace_with_deep_java_shape() {
    let temp = generated_java_workspace(1_000, 256, false);
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["DeepRoot"],"include_tests":true,"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "DeepRoot.java"),
        "payload: {value}"
    );
}

#[test]
#[ignore = "expensive 10k-file stack-safety smoke; run explicitly with cargo test --test searchtools_service -- --ignored"]
fn service_initializes_ten_thousand_tracked_java_files_without_stack_overflow() {
    let temp = generated_java_workspace(10_000, 512, true);
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["Generated9999"],"include_tests":true,"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "Generated9999.java"),
        "payload: {value}"
    );
}

fn generated_java_workspace(file_count: usize, nested_depth: usize, tracked: bool) -> TempDir {
    let temp = TempDir::new().unwrap();
    let mut paths = Vec::with_capacity(file_count + 1);

    let deep_path = temp.path().join("DeepRoot.java");
    fs::write(&deep_path, deep_java_source(nested_depth)).unwrap();
    paths.push(PathBuf::from("DeepRoot.java"));

    for index in 0..file_count {
        let rel = PathBuf::from(format!("Generated{index}.java"));
        fs::write(
            temp.path().join(&rel),
            format!("public class Generated{index} {{ int value() {{ return {index}; }} }}\n"),
        )
        .unwrap();
        paths.push(rel);
    }

    if tracked {
        let repo = Repository::init(temp.path()).unwrap();
        let mut index = repo.index().unwrap();
        for path in &paths {
            index.add_path(path).unwrap();
        }
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test User", "test@example.com").unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "generated",
            &tree,
            &[],
        )
        .unwrap();
    }

    temp
}

fn deep_java_source(depth: usize) -> String {
    let mut source = String::from("public class DeepRoot {\n");
    for index in 0..depth {
        source.push_str(&format!("static class Nested{index} {{\n"));
    }
    source.push_str("int value() { return 1; }\n");
    for _ in 0..depth {
        source.push_str("}\n");
    }
    source.push_str("}\n");
    source
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

fn commit_paths_with_removals(repo: &Repository, add: &[&str], remove: &[&str], message: &str) {
    let mut index = repo.index().unwrap();
    for path in add {
        index.add_path(std::path::Path::new(path)).unwrap();
    }
    for path in remove {
        index.remove_path(std::path::Path::new(path)).unwrap();
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

#[test]
fn semantic_search_reports_disabled_without_indexer() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_value(
            "semantic_search",
            serde_json::json!({ "query": "anything", "k": 1 }),
        )
        .expect_err("semantic_search must fail without an indexer");
    assert!(
        err.message.contains("disabled") || err.message.contains("not available"),
        "unexpected error message: {}",
        err.message
    );
}

#[test]
fn semantic_search_status_reports_disabled_without_indexer() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_value("semantic_search_status", serde_json::json!({}))
        .expect_err("semantic_search_status must fail without an indexer");
    assert!(
        err.message.contains("disabled") || err.message.contains("not available"),
        "unexpected error message: {}",
        err.message
    );
}
