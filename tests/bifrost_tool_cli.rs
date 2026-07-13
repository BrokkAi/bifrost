use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use git2::{Repository, Signature};
use serde_json::Value;
use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

fn get_file_contents_args(path: &Path) -> String {
    serde_json::json!({ "file_paths": [path] }).to_string()
}

fn get_file_contents_many(paths: &[&str]) -> String {
    serde_json::json!({ "file_paths": paths }).to_string()
}

fn commit_paths(repo: &Repository, paths: &[&str], message: &str) {
    let mut index = repo.index().unwrap();
    for path in paths {
        index.add_path(Path::new(path)).unwrap();
    }
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Bifrost Test", "bifrost@example.com").unwrap();
    let parents = if let Ok(head) = repo.head() {
        vec![head.peel_to_commit().unwrap()]
    } else {
        Vec::new()
    };
    let parent_refs: Vec<_> = parents.iter().collect();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parent_refs,
    )
    .unwrap();
}

#[test]
fn tool_get_summaries_prints_structured_json_without_content() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_summaries")
        .arg("--args")
        .arg(r#"{"targets":["A.java"]}"#)
        .output()
        .expect("run bifrost --tool get_summaries");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    assert_eq!(payload["isError"], false, "{payload}");
    assert!(payload.get("content").is_none(), "{payload}");
    assert_eq!(
        payload["structuredContent"]["summaries"][0]["path"], "A.java",
        "{payload}"
    );
    assert_eq!(
        payload["structuredContent"]["summaries"][0]["elements"][0]["start_line"], 3,
        "{payload}"
    );
}

#[test]
fn code_query_repl_accepts_piped_sexp_commands() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--repl")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost --repl");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(
                br#"(class
  :name "A")
:validate
:json
:run
:quit
"#,
            )
            .expect("write repl input");
    }
    let output = wait_with_output(child, Duration::from_secs(30));

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Query is valid."), "{stdout}");
    assert!(stdout.contains("\"kind\": \"class\""), "{stdout}");
    assert!(stdout.contains("A.java:3-52"), "{stdout}");
    assert!(stdout.contains("  kind: class"), "{stdout}");
    assert!(stdout.contains("  symbol: A"), "{stdout}");
    assert!(stdout.contains("  code: `public class A {"), "{stdout}");
}

fn wait_with_output(mut child: std::process::Child, timeout: Duration) -> std::process::Output {
    let started = Instant::now();
    loop {
        match child.try_wait().expect("poll child") {
            Some(_) => return child.wait_with_output().expect("wait for child output"),
            None if started.elapsed() >= timeout => {
                let _ = child.kill();
                let output = child.wait_with_output().expect("wait after killing child");
                panic!(
                    "child timed out after {:?}\nstdout:\n{}\nstderr:\n{}",
                    timeout,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[test]
fn tool_get_summaries_accepts_git_history_path() {
    let temp = TempDir::new().expect("temp dir");
    let root = temp.path();
    fs::write(
        root.join("Demo.java"),
        "class OldDemo {\n  int value() { return 1; }\n}\n",
    )
    .expect("write v1");
    let repo = Repository::init(root).expect("init repo");
    commit_paths(&repo, &["Demo.java"], "v1");
    fs::write(
        root.join("Demo.java"),
        "class NewDemo {\n  int value() { return 2; }\n}\n",
    )
    .expect("write v2");
    commit_paths(&repo, &["Demo.java"], "v2");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--tool")
        .arg("get_summaries")
        .arg("--args")
        .arg(r#"{"targets":["HEAD~1:Demo.java"]}"#)
        .output()
        .expect("run bifrost --tool get_summaries with git history path");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    let structured = &payload["structuredContent"];
    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        structured["summaries"][0]["elements"][0]["symbol"],
        "OldDemo"
    );
    assert!(
        structured["summaries"][0]["elements"][0]["text"]
            .as_str()
            .unwrap()
            .contains("OldDemo"),
        "{payload}"
    );
    assert!(
        !structured["summaries"][0]["elements"][0]["text"]
            .as_str()
            .unwrap()
            .contains("NewDemo"),
        "{payload}"
    );
}

#[test]
fn tool_get_symbol_sources_accepts_git_history_path() {
    let temp = TempDir::new().expect("temp dir");
    let root = temp.path();
    fs::write(
        root.join("Demo.java"),
        "class OldDemo {\n  int value() { return 1; }\n}\n",
    )
    .expect("write v1");
    let repo = Repository::init(root).expect("init repo");
    commit_paths(&repo, &["Demo.java"], "v1");
    fs::write(
        root.join("Demo.java"),
        "class NewDemo {\n  int value() { return 2; }\n}\n",
    )
    .expect("write v2");
    commit_paths(&repo, &["Demo.java"], "v2");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--tool")
        .arg("get_symbol_sources")
        .arg("--args")
        .arg(r#"{"symbols":["HEAD~1:Demo.java#OldDemo"]}"#)
        .output()
        .expect("run bifrost --tool get_symbol_sources with git history path");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    let source_text = payload["structuredContent"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|source| source["text"].as_str())
        .find(|text| text.contains("value() { return 1; }"))
        .expect("symbol source text");
    assert_eq!(payload["isError"], false, "{payload}");
    assert!(source_text.contains("OldDemo"), "{payload}");
    assert!(source_text.contains("value() { return 1; }"), "{payload}");
    assert!(!source_text.contains("NewDemo"), "{payload}");
}

#[test]
fn tool_get_symbol_sources_does_not_treat_colon_selectors_as_git_history() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_symbol_sources")
        .arg("--args")
        .arg(r#"{"symbols":["A.java:A.method2","A.java:A.rs","A.java:1-32"]}"#)
        .output()
        .expect("run bifrost --tool get_symbol_sources with colon selectors");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    let structured = &payload["structuredContent"];

    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        2,
        structured["sources"].as_array().unwrap().len(),
        "{payload}"
    );
    assert_eq!(
        2,
        structured["not_found"].as_array().unwrap().len(),
        "{payload}"
    );
    let not_found = structured["not_found"].as_array().unwrap();
    assert!(
        not_found.iter().any(|item| item["input"] == "A.java:A.rs"),
        "{payload}"
    );
    let range = not_found
        .iter()
        .find(|item| item["input"] == "A.java:1-32")
        .expect("line/range selector result");
    assert!(
        range["note"]
            .as_str()
            .unwrap()
            .contains("line/range anchor, not a symbol selector"),
        "{payload}"
    );
}

#[test]
fn tool_no_line_numbers_suppresses_line_prefixes() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_summaries")
        .arg("--args")
        .arg(r#"{"targets":["A.java"]}"#)
        .arg("--no-line-numbers")
        .output()
        .expect("run bifrost --tool get_summaries --no-line-numbers");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    let element = &payload["structuredContent"]["summaries"][0]["elements"][0];
    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        payload["structuredContent"]["summaries"][0]["path"],
        "A.java"
    );
    assert!(element["text"].as_str().unwrap().contains("public class A"));
    assert!(!element["text"].as_str().unwrap().contains("3..52:"));
}

#[test]
fn tool_normalizes_absolute_paths_inside_workspace() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--args")
        .arg(get_file_contents_args(&fixture_root().join("A.java")))
        .output()
        .expect("run bifrost --tool get_file_contents");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    assert_eq!(
        payload["structuredContent"]["files"][0]["path"], "A.java",
        "{payload}"
    );
    assert!(
        payload["structuredContent"]["files"][0]["content"].is_string(),
        "{payload}"
    );
}

#[test]
fn tool_rejects_absolute_paths_outside_workspace() {
    let outside = TempDir::new().expect("outside dir");
    let outside_file = outside.path().join("Outside.java");
    fs::write(&outside_file, "class Outside {}\n").expect("write outside file");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--args")
        .arg(get_file_contents_args(&outside_file))
        .output()
        .expect("run bifrost --tool get_file_contents");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("outside active workspace"), "{stderr}");
}

#[test]
fn tool_sources_limit_workspace_to_selected_files() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--sources")
        .arg("A.java")
        .arg("--args")
        .arg(get_file_contents_many(&["A.java", "B.java"]))
        .output()
        .expect("run bifrost --tool get_file_contents --sources A.java");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    let structured = &payload["structuredContent"];
    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        structured["files"].as_array().unwrap().len(),
        1,
        "{payload}"
    );
    assert_eq!(structured["files"][0]["path"], "A.java", "{payload}");
    assert_eq!(
        structured["not_found"],
        serde_json::json!(["B.java"]),
        "{payload}"
    );
}

#[test]
fn tool_sources_accept_absolute_workspace_paths() {
    let source = fixture_root().join("A.java");
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--sources")
        .arg(&source)
        .arg("--args")
        .arg(get_file_contents_args(&source))
        .output()
        .expect("run bifrost --tool get_file_contents --sources abs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        payload["structuredContent"]["files"][0]["path"], "A.java",
        "{payload}"
    );
}

#[test]
fn tool_sources_expand_directories_and_globs() {
    let temp = TempDir::new().expect("temp dir");
    let root = temp.path();
    fs::create_dir_all(root.join("src/nested")).expect("mkdirs");
    fs::write(root.join("src/A.java"), "class A {}\n").expect("write A");
    fs::write(root.join("src/nested/B.java"), "class B {}\n").expect("write B");
    fs::write(root.join("src/notes.txt"), "notes\n").expect("write notes");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--sources")
        .arg("src/*.java")
        .arg("--sources")
        .arg("src/nested")
        .arg("--args")
        .arg(get_file_contents_many(&[
            "src/A.java",
            "src/nested/B.java",
            "src/notes.txt",
        ]))
        .output()
        .expect("run bifrost --tool get_file_contents with glob + dir");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let payload: Value = serde_json::from_str(&stdout).expect("json stdout");
    let structured = &payload["structuredContent"];
    assert_eq!(payload["isError"], false, "{payload}");
    let files = structured["files"].as_array().expect("files array");
    assert_eq!(files.len(), 2, "{payload}");
    assert_eq!(files[0]["path"], "src/A.java", "{payload}");
    assert_eq!(files[1]["path"], "src/nested/B.java", "{payload}");
    assert_eq!(
        structured["not_found"],
        serde_json::json!(["src/notes.txt"]),
        "{payload}"
    );
}

#[test]
fn tool_sources_reject_absolute_paths_outside_workspace() {
    let outside = TempDir::new().expect("outside dir");
    let outside_file = outside.path().join("Outside.java");
    fs::write(&outside_file, "class Outside {}\n").expect("write outside file");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--sources")
        .arg(&outside_file)
        .arg("--args")
        .arg(get_file_contents_many(&["A.java"]))
        .output()
        .expect("run bifrost --tool get_file_contents with outside --sources");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("outside active workspace"), "{stderr}");
}

#[test]
fn tool_sources_reject_empty_glob_matches() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--sources")
        .arg("missing/**/*.java")
        .arg("--args")
        .arg(get_file_contents_many(&["A.java"]))
        .output()
        .expect("run bifrost --tool get_file_contents with empty glob");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("matched no files"), "{stderr}");
}

#[test]
fn tool_unknown_tool_is_reported() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("unknown_tool")
        .output()
        .expect("run bifrost --tool unknown_tool");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("Unknown tool"), "{stderr}");
}

#[test]
fn removed_search_ast_tool_name_is_reported_as_unknown() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("search_ast")
        .arg("--args")
        .arg(r#"{"match":{"kind":"class","name":"A"}}"#)
        .output()
        .expect("run bifrost with removed search_ast tool name");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("Unknown tool: search_ast"), "{stderr}");
}

#[test]
fn query_code_tool_returns_structural_matches() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("query_code")
        .arg("--args")
        .arg(r#"{"match":{"kind":"class","name":"A"}}"#)
        .output()
        .expect("run bifrost --tool query_code");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("query_code JSON output");
    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        payload["structuredContent"]["results"][0]["kind"], "class",
        "{payload}"
    );
    assert_eq!(
        payload["structuredContent"]["results"][0]["result_type"], "structural_match",
        "{payload}"
    );
}

#[test]
fn query_file_runs_rql_from_the_current_workspace() {
    let root = TempDir::new().expect("workspace");
    fs::write(root.path().join("app.py"), "class App:\n    pass\n").expect("source file");
    let queries = root.path().join("queries");
    fs::create_dir(&queries).expect("query directory");
    fs::write(queries.join("app.rql"), "(file-of (class :name \"App\"))\n").expect("RQL query");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .current_dir(root.path())
        .arg("--query-file")
        .arg("queries/app.rql")
        .output()
        .expect("run bifrost --query-file");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("query-file JSON output");
    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        payload["structuredContent"]["results"][0]["result_type"], "file",
        "{payload}"
    );
    assert_eq!(
        payload["structuredContent"]["results"][0]["path"], "app.py",
        "{payload}"
    );
}

#[test]
fn query_file_runs_json_with_an_explicit_root() {
    let root = TempDir::new().expect("workspace");
    fs::write(root.path().join("app.py"), "class App:\n    pass\n").expect("source file");
    let queries = root.path().join("queries");
    fs::create_dir(&queries).expect("query directory");
    fs::write(
        queries.join("app.json"),
        r#"{"match":{"kind":"class","name":"App"}}"#,
    )
    .expect("JSON query");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root.path())
        .arg("--query-file")
        .arg("queries/app.json")
        .output()
        .expect("run bifrost --root --query-file");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("query-file JSON output");
    assert_eq!(payload["isError"], false, "{payload}");
    assert_eq!(
        payload["structuredContent"]["results"][0]["path"], "app.py",
        "{payload}"
    );
}

#[test]
fn query_file_rejects_tool_mode_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--query-file")
        .arg("query.rql")
        .arg("--tool")
        .arg("query_code")
        .output()
        .expect("run incompatible bifrost flags");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("--query-file cannot be combined with --tool"),
        "{stderr}"
    );
}

#[test]
fn tool_cannot_be_combined_with_mcp() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_summaries")
        .arg("--mcp")
        .arg("searchtools")
        .output()
        .expect("run invalid bifrost args");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("--tool cannot be combined with --mcp, --lsp, or --repl"),
        "{stderr}"
    );
}

#[test]
fn tool_sources_require_tool_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--sources")
        .arg("A.java")
        .output()
        .expect("run invalid bifrost args");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("--sources may only be used with --tool"),
        "{stderr}"
    );
}

#[test]
fn help_mentions_tool_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--help")
        .output()
        .expect("run bifrost --help");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("--tool NAME"), "{stdout}");
    assert!(stdout.contains("--query-file PATH"), "{stdout}");
    assert!(stdout.contains("--args"), "{stdout}");
    assert!(stdout.contains("--sources PATH"), "{stdout}");
    assert!(!stdout.contains("search_ast"), "{stdout}");
}

#[test]
fn query_code_help_includes_boundary_example_and_guide() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--help")
        .arg("query_code")
        .output()
        .expect("run bifrost --help query_code");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("query_code  (toolset: extended)"),
        "{stdout}"
    );
    assert!(stdout.contains("typed semantic steps"), "{stdout}");
    assert!(stdout.contains("imports_of"), "{stdout}");
    assert!(stdout.contains(r#"{"match":{"kind":"call""#), "{stdout}");
    assert!(!stdout.contains("search_ast"), "{stdout}");
    assert!(
        stdout.contains("https://brokkai.github.io/bifrost/code-querying/"),
        "{stdout}"
    );
}
