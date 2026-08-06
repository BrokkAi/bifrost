use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use git2::{Repository, Signature};
use serde_json::Value;
use tempfile::TempDir;

use crate::common::ScratchCacheDir;

/// The shared Java corpus, in place inside the repository.
///
/// A process rooted here resolves the checkout's own `.bifrost/cache`
/// database, so every spawned command that uses it must carry a
/// [`ScratchCacheDir`] (issue #1588).
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

fn snapshot_tree(root: &Path, objects: &Path, path: &str, contents: &str) -> String {
    fs::create_dir_all(objects).expect("create snapshot objects directory");
    let mut hash = Command::new("git");
    hash.arg("-C")
        .arg(root)
        .args(["hash-object", "-w", "--stdin"])
        .env("GIT_OBJECT_DIRECTORY", objects)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = hash.spawn().expect("spawn git hash-object");
    child
        .stdin
        .as_mut()
        .expect("hash stdin")
        .write_all(contents.as_bytes())
        .expect("write snapshot blob");
    let output = child.wait_with_output().expect("wait for git hash-object");
    assert!(
        output.status.success(),
        "git hash-object failed: {output:?}"
    );
    let blob = String::from_utf8(output.stdout)
        .expect("blob oid utf8")
        .trim()
        .to_string();

    let mut mktree = Command::new("git");
    mktree
        .arg("-C")
        .arg(root)
        .arg("mktree")
        .env("GIT_OBJECT_DIRECTORY", objects)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = mktree.spawn().expect("spawn git mktree");
    child
        .stdin
        .as_mut()
        .expect("mktree stdin")
        .write_all(format!("100644 blob {blob}\t{path}\n").as_bytes())
        .expect("write snapshot tree");
    let output = child.wait_with_output().expect("wait for git mktree");
    assert!(output.status.success(), "git mktree failed: {output:?}");
    String::from_utf8(output.stdout)
        .expect("tree oid utf8")
        .trim()
        .to_string()
}

#[test]
fn tool_get_summaries_prints_structured_json_without_content() {
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let mut child = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let output = wait_with_output(child, Duration::from_secs(120));

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

// #1216: a committed filename containing `#` (e.g.
// `dir/Foo.VerifyGeneratedCode#01.verified.cs`) must be addressable via the
// CLI as `REV:path#symbol` without the historical loader truncating the path
// at the first `#`. End-to-end: real git repo fixture, real historical
// source loading through the actual `bifrost` binary.
#[test]
fn tool_get_symbol_sources_git_history_hash_named_file_resolves_symbol() {
    let temp = TempDir::new().expect("temp dir");
    let root = temp.path();
    fs::write(
        root.join("Foo#bar.py"),
        "class OldDemo:\n    def value(self):\n        return 1\n",
    )
    .expect("write v1");
    let repo = Repository::init(root).expect("init repo");
    commit_paths(&repo, &["Foo#bar.py"], "v1");
    fs::write(
        root.join("Foo#bar.py"),
        "class NewDemo:\n    def value(self):\n        return 2\n",
    )
    .expect("write v2");
    commit_paths(&repo, &["Foo#bar.py"], "v2");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--tool")
        .arg("get_symbol_sources")
        .arg("--args")
        .arg(r#"{"symbols":["HEAD~1:Foo#bar.py#OldDemo"]}"#)
        .output()
        .expect("run bifrost --tool get_symbol_sources with hash-named git history path");

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
        0,
        structured["not_found"].as_array().unwrap().len(),
        "{payload}"
    );
    let source_text = structured["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|source| source["text"].as_str())
        .find(|text| text.contains("value(self)"))
        .expect("symbol source text");
    assert!(source_text.contains("OldDemo"), "{payload}");
    assert!(source_text.contains("return 1"), "{payload}");
    assert!(!source_text.contains("NewDemo"), "{payload}");
    assert!(!source_text.contains("return 2"), "{payload}");
}

// #1216 acceptance criterion: when both a short path (`Demo.py`) and a
// longer `#`-bearing path (`Demo.py#extra.py`) are committed at the same
// revision, the CLI-normalized historical selector must resolve against the
// longest resolvable path, not the first `#`.
//
// Note: both paths are removed from the *current* HEAD (only the long path
// is restored there) so the workspace's plain file listing cannot supply
// `Demo.py` as an ordinary file. That isolates the assertion to the git
// history loader's own split decision -- otherwise get_symbol_sources' own
// (already correct, #1131) anchor resolver would independently pick apart
// the reconstructed `path#symbol` string against whatever plain files happen
// to exist on disk, and a forward, first-match walk over two anchors that
// both exist as ordinary files would pick the short one first regardless of
// what this fix does.
#[test]
fn tool_get_symbol_sources_git_history_prefix_collision_selects_longest_path() {
    let temp = TempDir::new().expect("temp dir");
    let root = temp.path();
    fs::write(
        root.join("Demo.py"),
        "class Foo:\n    def value(self):\n        return 1\n",
    )
    .expect("write short file");
    fs::write(
        root.join("Demo.py#extra.py"),
        "class Bar:\n    def value(self):\n        return 2\n",
    )
    .expect("write long file");
    let repo = Repository::init(root).expect("init repo");
    commit_paths(
        &repo,
        &["Demo.py", "Demo.py#extra.py"],
        "v1: both paths present (the collision)",
    );

    fs::remove_file(root.join("Demo.py")).expect("remove short file from workdir");
    let mut index = repo.index().expect("repo index");
    index
        .remove_path(Path::new("Demo.py"))
        .expect("unstage short file");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = Signature::now("Bifrost Test", "bifrost@example.com").unwrap();
    let parent = repo.head().unwrap().peel_to_commit().unwrap();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "v2: drop short path",
        &tree,
        &[&parent],
    )
    .expect("commit v2");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--tool")
        .arg("get_symbol_sources")
        .arg("--args")
        .arg(r#"{"symbols":["HEAD~1:Demo.py#extra.py#Bar"]}"#)
        .output()
        .expect("run bifrost --tool get_symbol_sources with a prefix-colliding git history path");

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
        0,
        structured["not_found"].as_array().unwrap().len(),
        "{payload}"
    );
    let source_text = structured["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|source| source["text"].as_str())
        .find(|text| text.contains("value(self)"))
        .expect("symbol source text");
    assert!(source_text.contains("Bar"), "{payload}");
    assert!(source_text.contains("return 2"), "{payload}");
    assert!(!source_text.contains("Foo"), "{payload}");
    assert!(!source_text.contains("return 1"), "{payload}");
}

#[test]
fn tool_get_symbol_sources_does_not_treat_colon_selectors_as_git_history() {
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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

    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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

    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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

    // The registry-generated toolset listing in `--help` must not resurrect the removed name.
    let help = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--help")
        .output()
        .expect("run bifrost --help");
    assert!(
        help.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&help.stderr)
    );
    let help_stdout = String::from_utf8(help.stdout).expect("utf8 stdout");
    assert!(!help_stdout.contains("search_ast"), "{help_stdout}");
}

#[test]
fn analyze_diff_remains_available_in_tool_cli() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let repo = Repository::init(root).expect("init repo");
    fs::write(root.join("lib.rs"), "pub fn answer() -> i32 { 1 }\n").expect("write base");
    commit_paths(&repo, &["lib.rs"], "base");
    fs::write(root.join("lib.rs"), "pub fn answer() -> i32 { 2 }\n").expect("write change");
    commit_paths(&repo, &["lib.rs"], "change");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--tool")
        .arg("analyze_diff")
        .arg("--args")
        .arg(r#"{"target":"HEAD"}"#)
        .output()
        .expect("run bifrost --tool analyze_diff");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(payload["isError"], false, "{payload}");
    assert!(payload["structuredContent"]["endpoints"]["target"].is_string());
}

#[test]
fn analyze_diff_cli_reads_immutable_trees_from_configured_snapshot_objects() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let repo = Repository::init(root).expect("init repo");
    fs::write(root.join("lib.go"), "package sample\nfunc LiveHead() {}\n").expect("write head");
    commit_paths(&repo, &["lib.go"], "head");

    let objects = temp.path().join("snapshot-objects");
    let baseline = snapshot_tree(
        root,
        &objects,
        "lib.go",
        "package sample\nfunc CapturedBefore() {}\n",
    );
    let after = snapshot_tree(
        root,
        &objects,
        "lib.go",
        "package sample\nfunc CapturedAfter() {}\n",
    );

    fs::write(
        root.join("lib.go"),
        "package sample\nfunc MutatedLive() {}\n",
    )
    .expect("mutate worktree");
    fs::write(
        root.join("unrelated.go"),
        "package sample\nfunc AddedLive() {}\n",
    )
    .expect("add live file");

    let args = serde_json::json!({"base": baseline, "target": after}).to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--diff-snapshot-object-dir")
        .arg(&objects)
        .arg("--tool")
        .arg("analyze_diff")
        .arg("--args")
        .arg(&args)
        .output()
        .expect("run snapshot analyze_diff");
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(payload["isError"], false, "{payload}");
    let result = &payload["structuredContent"];
    assert_eq!(result["endpoints"]["base"], format!("tree:{baseline}"));
    assert_eq!(result["endpoints"]["target"], format!("tree:{after}"));
    let deleted = result["patch_symbols"]["deleted"]
        .as_array()
        .expect("deleted symbols");
    assert!(
        deleted
            .iter()
            .any(|record| record["before"]["name"] == "CapturedBefore"),
        "{result}"
    );
    let introduced = result["patch_symbols"]["introduced"]
        .as_array()
        .expect("introduced symbols");
    assert!(
        introduced
            .iter()
            .any(|record| record["after"]["name"] == "CapturedAfter"),
        "{result}"
    );
    assert!(
        introduced
            .iter()
            .all(|record| record["after"]["name"] != "MutatedLive"),
        "{result}"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--tool")
        .arg("analyze_diff")
        .arg("--args")
        .arg(args)
        .output()
        .expect("run snapshot analyze_diff without alternate");
    assert!(!output.status.success(), "missing alternate should fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unable to resolve revision"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn diff_snapshot_object_dir_rejects_missing_path() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let repo = Repository::init(root).expect("init repo");
    fs::write(root.join("lib.rs"), "pub fn answer() -> i32 { 1 }\n").expect("write source");
    commit_paths(&repo, &["lib.rs"], "base");
    let missing_objects = root.join("missing-snapshot-objects");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--diff-snapshot-object-dir")
        .arg(&missing_objects)
        .arg("--tool")
        .arg("analyze_diff")
        .arg("--args")
        .arg("{}")
        .output()
        .expect("run bifrost --tool analyze_diff with missing snapshot objects");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");

    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("Failed to resolve --diff-snapshot-object-dir"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&missing_objects.display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains("--diff-snapshot-object-dir must name a directory"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "stderr:\n{stderr}");
}

#[test]
fn diff_snapshot_object_dir_rejects_missing_path_for_mcp_launch() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let missing_objects = root.join("missing-snapshot-objects");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--diff-snapshot-object-dir")
        .arg(&missing_objects)
        .arg("--mcp")
        .arg("searchtools")
        // Prevent a missing validation call from hanging on inherited stdin.
        .stdin(Stdio::null())
        .output()
        .expect("run bifrost MCP with missing snapshot objects");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");

    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("Failed to resolve --diff-snapshot-object-dir"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&missing_objects.display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains("--diff-snapshot-object-dir must name a directory"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "stderr:\n{stderr}");
}

#[test]
fn diff_snapshot_object_dir_rejects_regular_file() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let repo = Repository::init(root).expect("init repo");
    fs::write(root.join("lib.rs"), "pub fn answer() -> i32 { 1 }\n").expect("write source");
    commit_paths(&repo, &["lib.rs"], "base");
    let objects_file = root.join("snapshot-objects-file");
    fs::write(&objects_file, "not a directory\n").expect("write snapshot objects file");
    let canonical_objects_file = objects_file
        .canonicalize()
        .expect("canonical snapshot objects file");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .arg("--diff-snapshot-object-dir")
        .arg(&objects_file)
        .arg("--tool")
        .arg("analyze_diff")
        .arg("--args")
        .arg("{}")
        .output()
        .expect("run bifrost --tool analyze_diff with snapshot objects file");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");

    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("--diff-snapshot-object-dir must name a directory"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&canonical_objects_file.display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Failed to resolve --diff-snapshot-object-dir"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "stderr:\n{stderr}");
}

#[test]
fn diff_snapshot_object_dir_rejects_regular_file_for_rootless_mcp_launch() {
    let temp = TempDir::new().expect("tempdir");
    let objects_file = temp.path().join("snapshot-objects-file");
    fs::write(&objects_file, "not a directory\n").expect("write snapshot objects file");
    let canonical_objects_file = objects_file
        .canonicalize()
        .expect("canonical snapshot objects file");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--diff-snapshot-object-dir")
        .arg(&objects_file)
        .arg("--mcp")
        .arg("searchtools")
        // Prevent a missing validation call from hanging on inherited stdin.
        .stdin(Stdio::null())
        .output()
        .expect("run rootless bifrost MCP with snapshot objects file");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");

    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("--diff-snapshot-object-dir must name a directory"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&canonical_objects_file.display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Failed to resolve --diff-snapshot-object-dir"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "stderr:\n{stderr}");
}

#[test]
fn diff_snapshot_object_dir_is_rejected_for_lsp() {
    let temp = TempDir::new().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--diff-snapshot-object-dir")
        .arg(temp.path())
        .arg("--lsp")
        .output()
        .expect("run bifrost --lsp with snapshot objects");
    assert!(!output.status.success(), "incompatible mode should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("--diff-snapshot-object-dir"), "{stderr}");
    assert!(stderr.contains("--lsp"), "{stderr}");
}

#[test]
fn query_code_tool_returns_structural_matches() {
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
fn query_code_tool_returns_versioned_explain_and_profile_reports() {
    let cache = ScratchCacheDir::new();
    let explain = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("query_code")
        .arg("--args")
        .arg(r#"{"execution_mode":"explain","match":{"kind":"class","name":"A"}}"#)
        .output()
        .expect("run query_code explain");
    assert!(
        explain.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&explain.stderr)
    );
    let explain: Value = serde_json::from_slice(&explain.stdout).expect("explain JSON output");
    assert_eq!(
        explain["structuredContent"]["format"],
        "bifrost_code_query_explain/v1"
    );
    assert_eq!(
        explain["structuredContent"]["scheduling"]["selected"],
        "sequential"
    );
    assert!(explain["structuredContent"].get("results").is_none());

    let cache = ScratchCacheDir::new();
    let profile = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("query_code")
        .arg("--args")
        .arg(r#"{"execution_mode":"profile","match":{"kind":"class","name":"A"}}"#)
        .output()
        .expect("run query_code profile");
    assert!(
        profile.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&profile.stderr)
    );
    let profile: Value = serde_json::from_slice(&profile.stdout).expect("profile JSON output");
    assert_eq!(
        profile["structuredContent"]["format"],
        "bifrost_code_query_profile/v2"
    );
    assert_eq!(
        profile["structuredContent"]["result"]["results"][0]["kind"],
        "class"
    );
    assert!(
        profile["structuredContent"]["operators"]
            .as_array()
            .is_some_and(|operators| !operators.is_empty())
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
fn query_file_runs_direct_importers_pipeline() {
    let root = TempDir::new().expect("workspace");
    fs::write(root.path().join("target.rb"), "def target; end\n").expect("target source");
    fs::write(
        root.path().join("first_importer.rb"),
        "require_relative 'target'\ndef first; end\n",
    )
    .expect("first importer source");
    fs::write(
        root.path().join("second_importer.rb"),
        "require_relative 'target'\ndef second; end\n",
    )
    .expect("second importer source");
    let queries = root.path().join("queries");
    fs::create_dir(&queries).expect("query directory");
    fs::write(
        queries.join("importers.rql"),
        "(importers-of (file-of (language ruby (function :name \"target\"))))\n",
    )
    .expect("RQL query");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .current_dir(root.path())
        .arg("--query-file")
        .arg("queries/importers.rql")
        .output()
        .expect("run bifrost --query-file importers pipeline");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("query-file JSON output");
    assert_eq!(payload["isError"], false, "{payload}");
    let results = payload["structuredContent"]["results"]
        .as_array()
        .expect("file results");
    assert_eq!(results.len(), 2, "{payload}");
    assert_eq!(results[0]["result_type"], "file", "{payload}");
    assert_eq!(results[0]["path"], "first_importer.rb", "{payload}");
    assert_eq!(results[1]["path"], "second_importer.rb", "{payload}");
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    let cache = ScratchCacheDir::new();
    let output = cache
        .command(env!("CARGO_BIN_EXE_bifrost"))
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
    assert!(
        stdout.contains(r#"{"schema_version":1,"match":{"kind":"method","name":"run"}"#),
        "{stdout}"
    );
    assert!(!stdout.contains("search_ast"), "{stdout}");
    assert!(
        stdout.contains("https://bifrost.brokk.ai/code-querying/"),
        "{stdout}"
    );
}
