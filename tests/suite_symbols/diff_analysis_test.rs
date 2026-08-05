use brokk_bifrost::SearchToolsService;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Comfortably above the usage-graph callsite cap
/// (`analyzer::usages::inverted_edges::MAX_CALLSITES`, currently 1000), so a
/// generated fixture reliably trips the large-callsite truncation notice.
const CALLSITES_ABOVE_CAP: usize = 1_200;

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

/// `git init` plus the identity every commit here needs.
///
/// `branch` pins the initial branch for tests that resolve it by name, without
/// `git init -b`: that flag needs Git 2.28, while `symbolic-ref` on an unborn
/// HEAD works on every version the project supports.
fn init_repo(root: &Path, branch: Option<&str>) {
    git(root, &["init"]);
    if let Some(branch) = branch {
        git(
            root,
            &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
        );
    }
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
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

fn git_output(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run git");
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn patch_array<'a>(result: &'a Value, pointer: &str) -> &'a Vec<Value> {
    result
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array at {pointer}: {result}"))
}

/// The `patch_symbols.edited` pair for `name`.
///
/// Matched symbols share a key of fqn, kind and language across endpoints, so
/// the two descriptors always carry the same `name` and either side finds the
/// same record; this looks at `after` for concreteness.
fn edited<'a>(result: &'a Value, name: &str) -> Option<&'a Value> {
    patch_array(result, "/patch_symbols/edited")
        .iter()
        .find(|pair| pair["after"]["name"].as_str() == Some(name))
}

fn introduced<'a>(result: &'a Value, name: &str) -> Option<&'a Value> {
    patch_array(result, "/patch_symbols/introduced")
        .iter()
        .find(|record| record["after"]["name"].as_str() == Some(name))
}

fn deleted<'a>(result: &'a Value, name: &str) -> Option<&'a Value> {
    patch_array(result, "/patch_symbols/deleted")
        .iter()
        .find(|record| record["before"]["name"].as_str() == Some(name))
}

fn alternate_tree(root: &Path, objects: &Path, path: &str, contents: &str) -> String {
    fs::create_dir_all(objects).unwrap();
    // `hash-object` reads its blob from stdin, so create it through a direct
    // command rather than the generic output helper.
    let mut hash = Command::new("git");
    hash.arg("-C")
        .arg(root)
        .args(["hash-object", "-w", "--stdin"])
        .env("GIT_OBJECT_DIRECTORY", objects)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = hash.spawn().expect("spawn hash-object");
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let blob = String::from_utf8(output.stdout).unwrap().trim().to_string();
    let tree_input = format!("100644 blob {blob}\t{path}\n");
    let mut mktree = Command::new("git");
    mktree
        .arg("-C")
        .arg(root)
        .arg("mktree")
        .env("GIT_OBJECT_DIRECTORY", objects)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = mktree.spawn().expect("spawn mktree");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(tree_input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn alternate_tree_entries(root: &Path, objects: &Path, entries: &[(&str, &[u8])]) -> String {
    fs::create_dir_all(objects).unwrap();
    let mut tree_input = String::new();
    for (path, contents) in entries {
        let mut hash = Command::new("git");
        hash.arg("-C")
            .arg(root)
            .args(["hash-object", "-w", "--stdin"])
            .env("GIT_OBJECT_DIRECTORY", objects)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let mut child = hash.spawn().unwrap();
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(contents).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let blob = String::from_utf8(output.stdout).unwrap().trim().to_string();
        tree_input.push_str(&format!("100644 blob {blob}\t{path}\n"));
    }
    let mut mktree = Command::new("git");
    mktree
        .arg("-C")
        .arg(root)
        .arg("mktree")
        .env("GIT_OBJECT_DIRECTORY", objects)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = mktree.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(tree_input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn analyze_diff_reports_symbol_and_edge_effects() {
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
                "analyze_diff",
                &serde_json::json!({"target": head}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json");

    assert_eq!(
        result["endpoints"]["target"].as_str().unwrap(),
        head,
        "resolved target hash is returned"
    );
    assert_eq!(
        result["endpoints"]["base"].as_str().unwrap().len(),
        40,
        "`base` defaults to the resolved first parent"
    );
    // Symbol effects live entirely under `patch_symbols`; nothing about them is
    // published at the top level or split by endpoint.
    for field in ["moved_symbols", "signature_changes", "changed_test_symbols"] {
        assert!(
            result.get(field).is_none(),
            "`{field}` must not be a top-level field: {result}"
        );
    }
    for side in ["preimage", "postimage"] {
        assert!(
            result["patch_symbols"].get(side).is_none(),
            "`patch_symbols.{side}` must not exist: {result}"
        );
    }

    let existing = edited(&result, "Existing").expect("Existing edited");
    assert!(
        existing["before"]["fqn"]
            .as_str()
            .unwrap()
            .ends_with("Existing")
    );
    assert_eq!(existing["before"]["path"], "lib.go");
    assert_eq!(existing["after"]["path"], "lib.go");
    assert_eq!(existing["touched_old_lines"], serde_json::json!([4]));
    assert_eq!(existing["touched_new_lines"], serde_json::json!([6, 7]));

    let added = introduced(&result, "Added").expect("Added introduced");
    assert!(added["after"]["fqn"].as_str().unwrap().ends_with("Added"));
    assert_eq!(added["after"]["path"], "lib.go");
    assert!(
        added.get("touched_old_lines").is_none(),
        "an introduced symbol has no preimage side: {added}"
    );
    assert!(!added["touched_new_lines"].as_array().unwrap().is_empty());

    assert!(
        result["import_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["added"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str().unwrap().contains("strings")))
    );
    assert!(
        result["call_edge_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["change"] == "added")
    );
}

/// Commits `before`, then `after`, and returns `analyze_diff` over that pair.
fn analyze_single_file_edit(root: &Path, name: &str, before: &str, after: &str) -> Value {
    init_repo(root, None);
    fs::write(root.join(name), before).unwrap();
    commit(root, "base");
    fs::write(root.join(name), after).unwrap();
    let head = commit(root, "change");
    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"target": head}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json")
}

fn analyze(root: &Path, args: Value) -> Value {
    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    serde_json::from_str(
        &service
            .call_tool_json("analyze_diff", &args.to_string())
            .expect("analyze_diff"),
    )
    .expect("json")
}

fn analyze_error(root: &Path, args: Value) -> String {
    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    service
        .call_tool_json("analyze_diff", &args.to_string())
        .expect_err("analyze_diff should fail")
        .message
}

fn file_change<'a>(result: &'a Value, path: &str) -> &'a Value {
    result["file_changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == path || change["old_path"] == path)
        .unwrap_or_else(|| panic!("no file_change for {path}: {result}"))
}

/// Writes `contents` into the object database and stages it at `path` with an
/// explicit mode, which is how this suite produces symlink and gitlink entries
/// without depending on the host filesystem's symlink support.
fn stage_with_mode(root: &Path, path: &str, mode: &str, contents: &str) {
    let mut hash = Command::new("git");
    hash.arg("-C")
        .arg(root)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = hash.spawn().expect("spawn hash-object");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let blob = String::from_utf8(output.stdout).unwrap().trim().to_string();
    git(
        root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("{mode},{blob},{path}"),
        ],
    );
}

#[test]
fn analyze_diff_pairs_insertion_only_edit_across_both_endpoints() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let result = analyze_single_file_edit(
        root,
        "lib.go",
        "package sample\n\nfunc Existing() int {\n\tx := 1\n\treturn x\n}\n",
        "package sample\n\nfunc Existing() int {\n\tx := 1\n\tx += 1\n\treturn x\n}\n",
    );

    let pair = edited(&result, "Existing").expect("Existing edited");
    assert_eq!(pair["touched_new_lines"], serde_json::json!([5]));
    assert_eq!(
        pair["touched_old_lines"],
        serde_json::json!([]),
        "an insertion-only edit touches no preimage line: {pair}"
    );
    assert_eq!(
        pair["before"]["end_line"], 6,
        "the preimage descriptor keeps the base line range"
    );
    assert_eq!(pair["after"]["end_line"], 7);

    assert!(
        patch_array(&result, "/patch_symbols/deleted").is_empty(),
        "an edited symbol is not deleted: {result}"
    );
}

#[test]
fn analyze_diff_pairs_deletion_only_edit_across_both_endpoints() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let result = analyze_single_file_edit(
        root,
        "lib.go",
        "package sample\n\nfunc Existing() int {\n\tx := 1\n\tx += 1\n\treturn x\n}\n",
        "package sample\n\nfunc Existing() int {\n\tx := 1\n\treturn x\n}\n",
    );

    let pair = edited(&result, "Existing").expect("Existing edited");
    assert_eq!(pair["touched_old_lines"], serde_json::json!([5]));
    assert_eq!(
        pair["touched_new_lines"],
        serde_json::json!([]),
        "a deletion-only edit touches no postimage line: {pair}"
    );

    assert!(
        patch_array(&result, "/patch_symbols/introduced").is_empty(),
        "an edited symbol is not introduced: {result}"
    );
}

/// Every `edited` record describes the symbol at both endpoints, whatever shape
/// its hunks take, and the two line lists are what distinguish the shapes: an
/// insertion-only edit has no old-side lines, a deletion-only edit has no
/// new-side lines, and a replacement has both. This is the invariant #1518 was
/// about, now carried by the record itself rather than by two parallel lists.
#[test]
fn analyze_diff_edited_pairs_describe_both_endpoints() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    // Insertion-only, deletion-only and replacement edits in one patch, plus an
    // untouched function that must stay out of both lists.
    let result = analyze_single_file_edit(
        root,
        "lib.go",
        concat!(
            "package sample\n",
            "\n",
            "func Inserted() int {\n",
            "\tx := 1\n",
            "\treturn x\n",
            "}\n",
            "\n",
            "func Deleted() int {\n",
            "\ty := 2\n",
            "\ty += 2\n",
            "\treturn y\n",
            "}\n",
            "\n",
            "func Replaced() int {\n",
            "\treturn 3\n",
            "}\n",
            "\n",
            "func Untouched() int {\n",
            "\treturn 4\n",
            "}\n",
        ),
        concat!(
            "package sample\n",
            "\n",
            "func Inserted() int {\n",
            "\tx := 1\n",
            "\tx += 1\n",
            "\treturn x\n",
            "}\n",
            "\n",
            "func Deleted() int {\n",
            "\ty := 2\n",
            "\treturn y\n",
            "}\n",
            "\n",
            "func Replaced() int {\n",
            "\treturn 33\n",
            "}\n",
            "\n",
            "func Untouched() int {\n",
            "\treturn 4\n",
            "}\n",
        ),
    );

    let pairs = patch_array(&result, "/patch_symbols/edited");
    let mut names: Vec<&str> = pairs
        .iter()
        .map(|pair| pair["after"]["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["Deleted", "Inserted", "Replaced"],
        "only the three touched functions are edited: {result}"
    );

    for pair in pairs {
        let name = pair["after"]["name"].as_str().unwrap();
        assert_eq!(
            pair["before"]["name"], pair["after"]["name"],
            "{name}: a pair names one symbol at both endpoints: {pair}"
        );
        assert!(
            pair["before"]["start_line"].as_u64().is_some_and(|l| l > 0)
                && pair["after"]["start_line"].as_u64().is_some_and(|l| l > 0),
            "{name}: both descriptors carry a real source range: {pair}"
        );
        assert!(
            !pair["touched_old_lines"].as_array().unwrap().is_empty()
                || !pair["touched_new_lines"].as_array().unwrap().is_empty(),
            "{name}: an untouched symbol is not reported edited: {pair}"
        );
    }

    let empty = serde_json::json!([]);
    assert_eq!(
        edited(&result, "Inserted").unwrap()["touched_old_lines"],
        empty,
        "insertion-only: {result}"
    );
    assert_eq!(
        edited(&result, "Deleted").unwrap()["touched_new_lines"],
        empty,
        "deletion-only: {result}"
    );
    let replaced = edited(&result, "Replaced").unwrap();
    assert_ne!(
        replaced["touched_old_lines"], empty,
        "replacement: {result}"
    );
    assert_ne!(
        replaced["touched_new_lines"], empty,
        "replacement: {result}"
    );
}

/// A rename that moves a module without editing it changes every symbol's
/// fully-qualified name, so both endpoints hold symbols the other lacks -- and
/// neither overlaps a hunk, because a pure rename has no changed lines. This is
/// the documented boundary: the file change is reported, the symbols are not.
#[test]
fn analyze_diff_reports_a_pure_rename_without_patch_symbols() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    fs::create_dir(root.join("pkg_a")).unwrap();
    fs::write(
        root.join("pkg_a").join("mod.py"),
        "def fn():\n    return 1\n",
    )
    .unwrap();
    commit(root, "base");
    fs::create_dir(root.join("pkg_b")).unwrap();
    git(root, &["mv", "pkg_a/mod.py", "pkg_b/mod.py"]);
    let head = commit(root, "move");

    let result = analyze(root, serde_json::json!({"target": head}));
    let renamed = file_change(&result, "pkg_b/mod.py");
    assert_eq!(renamed["status"], "renamed");
    assert_eq!(renamed["old_path"], "pkg_a/mod.py");
    assert_eq!(renamed["insertions"], 0, "a pure rename changes no line");
    assert_eq!(renamed["deletions"], 0, "a pure rename changes no line");
    assert_eq!(renamed["is_binary"], false);
    for pointer in [
        "/patch_symbols/edited",
        "/patch_symbols/introduced",
        "/patch_symbols/deleted",
    ] {
        assert!(
            patch_array(&result, pointer).is_empty(),
            "{pointer} must be empty for a pure rename: {result}"
        );
    }
}

#[test]
fn analyze_diff_reports_a_source_deleted_from_the_working_tree() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Gone() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    commit(root, "base");
    fs::remove_file(root.join("lib.go")).unwrap();

    let result = analyze(root, serde_json::json!({}));
    assert_eq!(file_change(&result, "lib.go")["status"], "deleted");
    let gone = deleted(&result, "Gone")
        .unwrap_or_else(|| panic!("Gone must be reported deleted: {result}"));
    assert_eq!(gone["touched_old_lines"], serde_json::json!([3, 4, 5]));
    assert!(
        gone.get("touched_new_lines").is_none(),
        "a deleted symbol has no postimage side: {gone}"
    );
}

/// The `language` and `kind` strings on a patch symbol are part of the tool's
/// contract, so exercise them across the languages a mixed repository holds
/// rather than trusting the single-language fixtures elsewhere in this file.
#[test]
fn analyze_diff_labels_language_and_kind_per_source_file() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    let sources: [(&str, &str, &str, &str, &str); 5] = [
        (
            "lib.go",
            "package sample\n\nfunc Go() int {\n\treturn {N}\n}\n",
            "Go",
            "go",
            "function",
        ),
        (
            "mod.py",
            "def py_fn():\n    return {N}\n",
            "py_fn",
            "python",
            "function",
        ),
        (
            "Main.java",
            "class Main {\n    int java() {\n        return {N};\n    }\n}\n",
            "java",
            "java",
            "function",
        ),
        (
            "app.ts",
            "export function ts(): number {\n    return {N};\n}\n",
            "ts",
            "typescript",
            "function",
        ),
        (
            "lib.rs",
            "pub fn rs() -> i32 {\n    {N}\n}\n",
            "rs",
            "rust",
            "function",
        ),
    ];
    for (name, template, ..) in &sources {
        fs::write(root.join(name), template.replace("{N}", "1")).unwrap();
    }
    commit(root, "base");
    for (name, template, ..) in &sources {
        fs::write(root.join(name), template.replace("{N}", "2")).unwrap();
    }
    let head = commit(root, "change");

    let result = analyze(root, serde_json::json!({"target": head}));
    for (name, _, symbol, language, kind) in &sources {
        let found = &edited(&result, symbol)
            .unwrap_or_else(|| panic!("{name}: no edited symbol {symbol}: {result}"))["after"];
        assert_eq!(found["language"], *language, "{name}");
        assert_eq!(found["kind"], *kind, "{name}");
        assert_eq!(found["path"], *name);
        assert_eq!(
            file_change(&result, name)["is_parseable"],
            true,
            "{name} is a parseable extension"
        );
    }
}

#[test]
fn analyze_diff_reports_removed_imports_and_call_edges() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let result = analyze_single_file_edit(
        root,
        "lib.go",
        concat!(
            "package sample\n",
            "\n",
            "import \"strings\"\n",
            "\n",
            "func Helper(s string) string {\n",
            "\treturn strings.TrimSpace(s)\n",
            "}\n",
            "\n",
            "func Caller() string {\n",
            "\treturn Helper(\" x \")\n",
            "}\n",
        ),
        concat!(
            "package sample\n",
            "\n",
            "func Helper(s string) string {\n",
            "\treturn s\n",
            "}\n",
            "\n",
            "func Caller() string {\n",
            "\treturn \"x\"\n",
            "}\n",
        ),
    );

    assert!(
        result["import_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["removed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str().unwrap().contains("strings"))),
        "the dropped import is reported as removed: {result}"
    );
    assert!(
        result["call_edge_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["change"] == "removed"
                && edge["from"].as_str().unwrap().ends_with("Caller")
                && edge["to"].as_str().unwrap().ends_with("Helper")),
        "the dropped call is reported as a removed edge: {result}"
    );
}

/// Kotlin synthesises a constructor declaration for a class's primary
/// constructor. Synthetic units have no source of their own, so they must never
/// appear as edited symbols even when the class body is patched.
#[test]
fn analyze_diff_omits_synthetic_declarations() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let result = analyze_single_file_edit(
        root,
        "Greeter.kt",
        "package sample\n\nclass Greeter(val name: String) {\n    fun greet(): String = \"hi\"\n}\n",
        concat!(
            "package sample\n",
            "\n",
            "class Greeter(val name: String) {\n",
            "    fun greet(): String = \"hello\"\n",
            "}\n",
            "\n",
            "fun make(): Greeter = Greeter(\"x\")\n",
        ),
    );

    assert!(
        edited(&result, "greet").is_some(),
        "the edited method is reported: {result}"
    );
    // Every descriptor the patch reports, from both endpoints of every record.
    let all: Vec<&Value> = patch_array(&result, "/patch_symbols/edited")
        .iter()
        .flat_map(|pair| [&pair["before"], &pair["after"]])
        .chain(
            patch_array(&result, "/patch_symbols/introduced")
                .iter()
                .map(|record| &record["after"]),
        )
        .chain(
            patch_array(&result, "/patch_symbols/deleted")
                .iter()
                .map(|record| &record["before"]),
        )
        .collect();
    assert!(
        all.iter()
            .all(|symbol| symbol["start_line"].as_u64().is_some_and(|line| line > 0)),
        "every reported symbol has a real source range: {result}"
    );
    assert!(
        !all.iter()
            .any(|symbol| symbol["fqn"] == "sample.Greeter.Greeter"),
        "the synthesised primary constructor is not a patch symbol: {result}"
    );
    // `make` constructs a Greeter, so the added edge points at the synthetic
    // constructor. It has no patch symbol, so it contributes no dependency.
    assert!(
        !result["dependency_symbols"]
            .as_array()
            .unwrap()
            .iter()
            .any(|symbol| symbol["fqn"] == "sample.Greeter.Greeter"),
        "a synthetic edge target is not a dependency symbol: {result}"
    );
}

#[test]
fn analyze_diff_rejects_a_working_tree_diff_before_the_first_commit() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    fs::write(root.join("lib.go"), "package sample\n\nfunc New() {}\n").unwrap();

    let error = analyze_error(root, serde_json::json!({}));
    assert!(
        error.contains("unable to default `base` to HEAD"),
        "unborn HEAD must be reported as a missing base, got: {error}"
    );
}

#[test]
fn analyze_diff_rejects_a_tag_object_that_does_not_peel_to_a_commit() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    fs::write(root.join("lib.go"), "package sample\n\nfunc Old() {}\n").unwrap();
    let first = commit(root, "base");
    fs::write(root.join("lib.go"), "package sample\n\nfunc New() {}\n").unwrap();
    let head = commit(root, "change");

    // An annotated tag on a blob is a tag object that peels to neither a commit
    // nor a tree, so it exercises the endpoint kind report rather than a peel.
    let blob = git_output(root, &["hash-object", "lib.go"]);
    git(
        root,
        &["tag", "-a", "blobtag", &blob, "-m", "tag on a blob"],
    );

    let error = analyze_error(root, serde_json::json!({"base": "blobtag", "target": head}));
    assert!(
        error.contains("a tag") && error.contains("not a commit or tree"),
        "tag endpoints must name the object kind, got: {error}"
    );

    // An annotated tag on a commit still peels and diffs normally.
    git(
        root,
        &["tag", "-a", "committag", &first, "-m", "tag on a commit"],
    );
    let result = analyze(
        root,
        serde_json::json!({"base": "committag", "target": head}),
    );
    assert_eq!(result["endpoints"]["base"], first);
}

#[test]
fn analyze_diff_skips_non_regular_tree_entries() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Existing() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    fs::write(root.join("notes.txt"), "plain\n").unwrap();
    commit(root, "base");

    // A new symlink, plus a regular file replaced by a symlink. Both are blobs
    // whose contents are a path, and neither may be exported as a source file.
    stage_with_mode(root, "link", "120000", "lib.go");
    stage_with_mode(root, "notes.txt", "120000", "docs/readme.md");
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Existing() int {\n\treturn 2\n}\n",
    )
    .unwrap();
    git(root, &["add", "lib.go"]);
    git(root, &["commit", "-m", "symlinks"]);
    let head = git_output(root, &["rev-parse", "HEAD"]);

    let result = analyze(root, serde_json::json!({"target": head}));
    assert_eq!(file_change(&result, "link")["status"], "added");
    // `find_similar` splits a mode change into a delete and an add before
    // similarity runs, so a file that became a symlink is reported as both.
    let notes_statuses: Vec<&str> = result["file_changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["path"] == "notes.txt" || change["old_path"] == "notes.txt")
        .map(|change| change["status"].as_str().unwrap())
        .collect();
    assert_eq!(notes_statuses, vec!["deleted", "added"], "{result}");
    assert_eq!(
        file_change(&result, "notes.txt")["is_parseable"],
        false,
        "a .txt path is not parseable whatever its mode"
    );
    assert!(
        edited(&result, "Existing").is_some(),
        "the regular source beside the symlinks is still analyzed: {result}"
    );
}

#[test]
fn analyze_diff_exports_nested_and_executable_sources() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    fs::create_dir_all(root.join("pkg").join("inner")).unwrap();
    let helper = root.join("pkg").join("inner").join("helper.go");
    let tool = root.join("pkg").join("inner").join("tool.go");
    fs::write(
        &helper,
        "package inner\n\nfunc Help() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    fs::write(
        &tool,
        "package inner\n\nfunc Tool() int {\n\treturn Help()\n}\n",
    )
    .unwrap();
    git(root, &["add", "."]);
    // Two sources sharing one nested directory, one of them executable: the
    // export walk must create `pkg/inner` once and accept the 100755 mode.
    git(root, &["update-index", "--chmod=+x", "pkg/inner/tool.go"]);
    git(root, &["commit", "-m", "base"]);

    fs::write(
        &helper,
        "package inner\n\nfunc Help() int {\n\treturn 2\n}\n",
    )
    .unwrap();
    fs::write(
        &tool,
        "package inner\n\nfunc Tool() int {\n\treturn Help() + 1\n}\n",
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-m", "change"]);
    let head = git_output(root, &["rev-parse", "HEAD"]);

    let result = analyze(root, serde_json::json!({"target": head}));
    let help =
        edited(&result, "Help").unwrap_or_else(|| panic!("nested source is exported: {result}"));
    assert!(
        edited(&result, "Tool").is_some(),
        "executable-mode source is exported: {result}"
    );
    assert_eq!(
        help["after"]["path"], "pkg/inner/helper.go",
        "paths stay workspace-relative with forward slashes"
    );
}

#[test]
fn analyze_diff_reports_conflicted_working_tree_paths() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, Some("master"));
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Existing() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    commit(root, "base");
    git(root, &["checkout", "-b", "other"]);
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Existing() int {\n\treturn 2\n}\n",
    )
    .unwrap();
    commit(root, "other side");
    git(root, &["checkout", "master"]);
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Existing() int {\n\treturn 3\n}\n",
    )
    .unwrap();
    commit(root, "our side");
    // A failing merge is the point: it leaves an unmerged index entry.
    let merged = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["merge", "other"])
        .status()
        .expect("run git merge");
    assert!(!merged.success(), "the merge must conflict");

    let result = analyze(root, serde_json::json!({}));
    assert_eq!(result["endpoints"]["target"], "worktree");
    assert_eq!(file_change(&result, "lib.go")["status"], "conflicted");
}

#[test]
fn analyze_diff_reads_from_bare_repo_without_worktree() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("source");
    fs::create_dir(&root).unwrap();
    git(&root, &["init"]);
    git(&root, &["config", "user.email", "tester@example.com"]);
    git(&root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("lib.go"),
        "package sample\nfunc A() int { return 1 }\n",
    )
    .unwrap();
    commit(&root, "base");
    fs::write(
        root.join("lib.go"),
        "package sample\nfunc A() int { return 2 }\nfunc B() int { return A() }\n",
    )
    .unwrap();
    let head = commit(&root, "change");

    let bare = temp.path().join("repo.git");
    let status = Command::new("git")
        .args(["clone", "--bare"])
        .arg(&root)
        .arg(&bare)
        .status()
        .expect("clone bare");
    assert!(status.success(), "git clone --bare failed");

    let result = analyze(&bare, serde_json::json!({"target": head}));
    assert_eq!(result["endpoints"]["target"].as_str().unwrap(), head);
    assert!(
        introduced(&result, "B")
            .is_some_and(|record| record["after"]["fqn"].as_str().unwrap().ends_with("B"))
    );

    // Omitting `target` means "the working tree", which a bare repository does
    // not have; the failure has to name that rather than surface as a panic.
    let error = analyze_error(&bare, serde_json::json!({"base": head}));
    assert!(
        error.contains("bare"),
        "a worktree endpoint on a bare repository must be refused, got: {error}"
    );
}

#[test]
fn analyze_diff_from_python_service_does_not_build_root_workspace_cache() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("lib.go"),
        "package sample\nfunc A() int { return 1 }\n",
    )
    .unwrap();
    fs::write(
        root.join("untouched.go"),
        "package sample\nfunc Untouched() int { return 1 }\n",
    )
    .unwrap();
    commit(root, "base");
    fs::write(
        root.join("lib.go"),
        "package sample\nfunc A() int { return 2 }\n",
    )
    .unwrap();
    let head = commit(root, "change");

    let service = SearchToolsService::new_for_python(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"target": head}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json");

    assert_eq!(result["endpoints"]["target"].as_str().unwrap(), head);
    assert!(
        !root.join(".bifrost").join("analyzer.db").exists(),
        "analyze_diff should not force the root workspace analyzer/cache"
    );
    assert!(
        !root
            .join(".bifrost")
            .join("cache")
            .join(brokk_bifrost::cache_db::cache_db_file_name())
            .exists(),
        "analyze_diff should honor FileSetProject's persistence opt-out"
    );
}

#[test]
fn analyze_diff_reports_renamed_file_touches_on_exact_image_paths() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("old.go"),
        r#"package sample

func Keep() int {
	return 1
}
"#,
    )
    .unwrap();
    commit(root, "base");

    git(root, &["mv", "old.go", "new.go"]);
    fs::write(
        root.join("new.go"),
        r#"package sample

func Keep() int {
	return 2
}
"#,
    )
    .unwrap();
    let head = commit(root, "rename and edit");

    let service = SearchToolsService::new(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"target": head}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json");

    // One record, two paths: the preimage descriptor and its touched old lines
    // resolve against `old.go`, the postimage side against `new.go`.
    let keep = edited(&result, "Keep").expect("Keep touched");
    assert_eq!(keep["before"]["path"], "old.go");
    assert_eq!(keep["after"]["path"], "new.go");
    assert_eq!(keep["touched_old_lines"], serde_json::json!([4]));
    assert_eq!(keep["touched_new_lines"], serde_json::json!([4]));
}

#[test]
fn analyze_diff_rejects_root_commit_without_explicit_base() {
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
            "analyze_diff",
            &serde_json::json!({"target": root_commit}).to_string(),
        )
        .unwrap_err();
    assert!(
        err.message.contains("root commit") && err.message.contains("explicit `base`"),
        "{}",
        err.message
    );
}

/// Issue #1102 (commit-analysis half): with `include_tests:false`, symbol
/// filtering is per declaration, not whole-file. A Rust file that adds both a
/// production function and an inline `#[cfg(test)] mod tests` must report the
/// production symbol as introduced while suppressing the inline test symbol.
/// Before the fix, the whole file was gated on `contains_tests`, so the
/// production symbol was suppressed too.
#[test]
fn analyze_diff_filters_test_symbols_per_declaration_not_whole_file() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(root.join("widget.rs"), "pub fn seed() -> u32 {\n    1\n}\n").unwrap();
    commit(root, "base");

    fs::write(
        root.join("widget.rs"),
        r#"pub fn seed() -> u32 {
    1
}

pub fn make_widget() -> u32 {
    7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(make_widget(), 7);
    }
}
"#,
    )
    .unwrap();
    let head = commit(root, "add production fn plus inline tests");

    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"target": head, "include_tests": false}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json");

    assert!(
        introduced(&result, "make_widget").is_some(),
        "production symbol should be introduced with include_tests:false: {result}"
    );
    assert!(
        introduced(&result, "it_works").is_none(),
        "inline test symbol must be filtered with include_tests:false: {result}"
    );
}

/// Working-tree mode: `{}` diffs HEAD against the uncommitted state, like
/// `git diff HEAD`. Modified tracked files and brand-new untracked files both
/// surface; files left alone do not.
#[test]
fn analyze_diff_defaults_to_head_versus_working_tree() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Existing() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    fs::write(
        root.join("untouched.go"),
        "package sample\n\nfunc Untouched() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    let head = commit(root, "base");

    // Uncommitted: one tracked file edited, one untracked file added, one file
    // left exactly as committed.
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Existing() int {\n\treturn 2\n}\n",
    )
    .unwrap();
    fs::write(
        root.join("fresh.go"),
        "package sample\n\nfunc Fresh() int {\n\treturn 3\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json("analyze_diff", &serde_json::json!({}).to_string())
            .expect("analyze_diff"),
    )
    .expect("json");

    assert_eq!(result["endpoints"]["base"].as_str().unwrap(), head);
    assert_eq!(result["endpoints"]["target"].as_str().unwrap(), "worktree");

    assert!(
        edited(&result, "Existing").is_some(),
        "uncommitted edit to a tracked file should surface: {result}"
    );
    assert!(
        introduced(&result, "Fresh").is_some(),
        "untracked new file should surface as introduced: {result}"
    );
    assert!(
        edited(&result, "Untouched").is_none() && introduced(&result, "Untouched").is_none(),
        "unchanged file must not appear: {result}"
    );

    let file_status = |path: &str| -> Option<String> {
        result["file_changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|change| change["path"].as_str() == Some(path))
            .map(|change| change["status"].as_str().unwrap().to_string())
    };
    assert_eq!(
        file_status("lib.go").as_deref(),
        Some("modified"),
        "{result}"
    );
    assert_eq!(
        file_status("fresh.go").as_deref(),
        Some("added"),
        "an untracked file is `added` relative to the base endpoint: {result}"
    );
    assert_eq!(file_status("untouched.go"), None, "{result}");
}

/// Working-tree mode with an explicit `base`: `{base: A}` is `git diff A`,
/// aggregating everything between `A` and the uncommitted state.
#[test]
fn analyze_diff_with_base_only_spans_commits_and_working_tree() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(root.join("lib.go"), "package sample\n").unwrap();
    let base = commit(root, "base");

    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Committed() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    commit(root, "committed change");

    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Committed() int {\n\treturn 1\n}\n\nfunc Uncommitted() int {\n\treturn 2\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": base}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json");

    assert_eq!(result["endpoints"]["base"].as_str().unwrap(), base);
    assert_eq!(result["endpoints"]["target"].as_str().unwrap(), "worktree");

    assert!(
        introduced(&result, "Committed").is_some(),
        "committed change since base should surface: {result}"
    );
    assert!(
        introduced(&result, "Uncommitted").is_some(),
        "uncommitted change should surface too: {result}"
    );
}

/// Range mode: `{base: A, target: C}` is the squash view of A..C. A symbol
/// added in B and removed again in C nets out to nothing.
#[test]
fn analyze_diff_range_reports_aggregate_not_per_commit_changes() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Original() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    let commit_a = commit(root, "a");

    // B: add a transient symbol plus a durable one.
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Original() int {\n\treturn 1\n}\n\nfunc Transient() int {\n\treturn 2\n}\n\nfunc Durable() int {\n\treturn 3\n}\n",
    )
    .unwrap();
    commit(root, "b");

    // C: revert the transient symbol, keep the durable one.
    fs::write(
        root.join("lib.go"),
        "package sample\n\nfunc Original() int {\n\treturn 1\n}\n\nfunc Durable() int {\n\treturn 3\n}\n",
    )
    .unwrap();
    let commit_c = commit(root, "c");

    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": commit_a, "target": commit_c}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json");

    assert_eq!(result["endpoints"]["base"].as_str().unwrap(), commit_a);
    assert_eq!(result["endpoints"]["target"].as_str().unwrap(), commit_c);

    assert!(
        introduced(&result, "Durable").is_some(),
        "symbol added in B and kept in C should surface: {result}"
    );
    assert!(
        introduced(&result, "Transient").is_none(),
        "symbol added in B and reverted in C must not surface: {result}"
    );
    assert!(
        deleted(&result, "Transient").is_none(),
        "a symbol that never existed at either endpoint must not be reported deleted: {result}"
    );
}

/// A merge commit has no unambiguous first-parent default, so `{target: merge}`
/// must fail with a message that names the fix.
#[test]
fn analyze_diff_rejects_merge_commit_without_explicit_base() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("lib.go"),
        "package sample\nfunc A() int { return 1 }\n",
    )
    .unwrap();
    commit(root, "base");
    git(root, &["branch", "side"]);

    fs::write(
        root.join("main_side.go"),
        "package sample\nfunc Main() int { return 1 }\n",
    )
    .unwrap();
    commit(root, "on main");

    git(root, &["checkout", "side"]);
    fs::write(
        root.join("other_side.go"),
        "package sample\nfunc Other() int { return 1 }\n",
    )
    .unwrap();
    commit(root, "on side");

    git(root, &["checkout", "-"]);
    git(root, &["merge", "--no-ff", "-m", "merge side", "side"]);

    let service =
        SearchToolsService::new_without_semantic_index(root.to_path_buf()).expect("service");
    let err = service
        .call_tool_json(
            "analyze_diff",
            &serde_json::json!({"target": "HEAD"}).to_string(),
        )
        .unwrap_err();
    assert!(
        err.message.contains("merge commit") && err.message.contains("HEAD^1"),
        "{}",
        err.message
    );

    // With an explicit base the same merge commit analyzes fine.
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": "HEAD^1", "target": "HEAD"}).to_string(),
            )
            .expect("analyze_diff"),
    )
    .expect("json");
    assert!(
        introduced(&result, "Other").is_some(),
        "merged-in symbol should surface against first parent: {result}"
    );
}

/// The working-tree endpoint analyzes the live project root, but must not leave
/// a workspace cache behind: a changed-file-only view must never become the
/// workspace's persisted picture of itself.
#[test]
fn analyze_diff_worktree_mode_writes_no_workspace_cache() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("lib.go"),
        "package sample\nfunc A() int { return 1 }\n",
    )
    .unwrap();
    commit(root, "base");
    fs::write(
        root.join("lib.go"),
        "package sample\nfunc A() int { return 2 }\n",
    )
    .unwrap();

    let service = SearchToolsService::new_for_python(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json("analyze_diff", &serde_json::json!({}).to_string())
            .expect("analyze_diff"),
    )
    .expect("json");

    assert_eq!(result["endpoints"]["target"].as_str().unwrap(), "worktree");
    assert!(
        !root
            .join(".bifrost")
            .join("cache")
            .join(brokk_bifrost::cache_db::cache_db_file_name())
            .exists(),
        "worktree-endpoint analyzer must stay ephemeral over the live project root"
    );
    assert!(
        !root.join(".bifrost").join("analyzer.db").exists(),
        "analyze_diff should not force the root workspace analyzer/cache"
    );
}

#[test]
fn analyze_diff_compares_unreachable_snapshot_trees_through_trusted_alternate() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
    fs::write(root.join("lib.go"), "package sample\nfunc Head() {}\n").unwrap();
    commit(root, "head");

    let objects = temp.path().join("snapshot-objects");
    let baseline = alternate_tree(
        root,
        &objects,
        "lib.go",
        "package sample\nfunc DirtyBeforeTurn() {}\n",
    );
    let after = alternate_tree(
        root,
        &objects,
        "lib.go",
        "package sample\nfunc Restored() {}\n",
    );

    let ordinary = SearchToolsService::new_without_semantic_index(root.to_path_buf()).unwrap();
    let error = ordinary
        .call_tool_json(
            "analyze_diff",
            &serde_json::json!({"base": baseline, "target": after}).to_string(),
        )
        .unwrap_err();
    assert!(error.message.contains("unable to resolve revision"));

    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .unwrap()
        .with_diff_snapshot_object_dir(objects.clone());
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": baseline, "target": after}).to_string(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["endpoints"]["base"], format!("tree:{baseline}"));
    assert_eq!(result["endpoints"]["target"], format!("tree:{after}"));
    assert!(deleted(&result, "DirtyBeforeTurn").is_some());
    assert!(introduced(&result, "Restored").is_some());

    let missing = temp.path().join("missing-objects");
    let missing_service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .unwrap()
        .with_diff_snapshot_object_dir(missing.clone());
    let error = missing_service
        .call_tool_json("analyze_diff", &serde_json::json!({}).to_string())
        .unwrap_err();
    assert!(error.message.contains(&missing.display().to_string()));
}

#[test]
fn analyze_diff_tree_endpoints_are_immutable_and_require_an_explicit_base() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
    fs::write(root.join("lib.go"), "package sample\nfunc Old() {}\n").unwrap();
    let base_commit = commit(root, "base");
    fs::write(root.join("lib.go"), "package sample\nfunc New() {}\n").unwrap();
    let target_commit = commit(root, "target");
    let base_tree = git_output(root, &["rev-parse", "HEAD~1^{tree}"]);
    let target_tree = git_output(root, &["rev-parse", "HEAD^{tree}"]);
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf()).unwrap();

    let before: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": base_tree, "target": target_tree}).to_string(),
            )
            .unwrap(),
    )
    .unwrap();
    fs::write(root.join("lib.go"), "package sample\nfunc Corrupt() {}\n").unwrap();
    fs::write(root.join(".gitattributes"), "*.go -diff\n").unwrap();
    let worktree_attributes: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": base_tree, "target": target_tree}).to_string(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        before, worktree_attributes,
        "immutable endpoints must ignore checkout attributes"
    );
    git(root, &["add", ".gitattributes"]);
    let staged_attributes: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": base_tree, "target": target_tree}).to_string(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        before, staged_attributes,
        "immutable endpoints must ignore checkout and index"
    );

    for (base, target, expected_base, expected_target) in [
        (
            &base_commit,
            &target_commit,
            base_commit.as_str(),
            target_commit.as_str(),
        ),
        (&base_commit, &target_tree, base_commit.as_str(), "tree"),
        (&base_tree, &target_commit, "tree", target_commit.as_str()),
        (&base_tree, &target_tree, "tree", "tree"),
    ] {
        let result: Value = serde_json::from_str(
            &service
                .call_tool_json(
                    "analyze_diff",
                    &serde_json::json!({"base": base, "target": target}).to_string(),
                )
                .unwrap(),
        )
        .unwrap();
        assert!(
            result["endpoints"]["base"]
                .as_str()
                .unwrap()
                .contains(expected_base)
        );
        assert!(
            result["endpoints"]["target"]
                .as_str()
                .unwrap()
                .contains(expected_target)
        );
        assert!(introduced(&result, "New").is_some());
    }

    let error = service
        .call_tool_json(
            "analyze_diff",
            &serde_json::json!({"target": target_tree}).to_string(),
        )
        .unwrap_err();
    assert!(error.message.contains("trees have no parent"));
    assert!(error.message.contains("explicit `base`"));
}

#[test]
fn analyze_diff_snapshot_interval_survives_dirty_revert_to_head() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
    let head_contents = "package sample\nfunc Head() {}\n";
    fs::write(root.join("lib.go"), head_contents).unwrap();
    commit(root, "head");
    fs::write(
        root.join("lib.go"),
        "package sample\nfunc DirtyBeforeTurn() {}\n",
    )
    .unwrap();
    let objects = temp.path().join("objects");
    let baseline = alternate_tree(
        root,
        &objects,
        "lib.go",
        "package sample\nfunc DirtyBeforeTurn() {}\n",
    );
    fs::write(
        root.join("lib.go"),
        "package sample\nfunc DuringTurn() {}\n",
    )
    .unwrap();
    fs::write(root.join("lib.go"), head_contents).unwrap();
    let after = alternate_tree(root, &objects, "lib.go", head_contents);
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .unwrap()
        .with_diff_snapshot_object_dir(objects);
    let worktree: Value =
        serde_json::from_str(&service.call_tool_json("analyze_diff", "{}").unwrap()).unwrap();
    assert!(
        worktree["file_changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|change| change["path"] != "lib.go")
    );
    let snapshot: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": baseline, "target": after}).to_string(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(snapshot["endpoints"]["base"], format!("tree:{baseline}"));
    assert_eq!(snapshot["endpoints"]["target"], format!("tree:{after}"));
    assert!(deleted(&snapshot, "DirtyBeforeTurn").is_some());
    assert!(introduced(&snapshot, "Head").is_some());
}

/// A tree base with no `target` must diff that immutable tree against the live
/// working tree. This is the one endpoint combination that mixes a
/// snapshot-only object with live state, so it exercises the non-isolated
/// repository handle: the alternate must still resolve the tree, while the
/// target side reads the real checkout.
#[test]
fn analyze_diff_tree_base_without_target_spans_snapshot_and_working_tree() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
    fs::write(root.join("lib.go"), "package sample\nfunc Committed() {}\n").unwrap();
    commit(root, "head");

    let objects = temp.path().join("objects");
    let base = alternate_tree(
        root,
        &objects,
        "lib.go",
        "package sample\nfunc SnapshotBase() {}\n",
    );
    fs::write(root.join("lib.go"), "package sample\nfunc LiveNow() {}\n").unwrap();

    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .unwrap()
        .with_diff_snapshot_object_dir(objects);
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({ "base": base }).to_string(),
            )
            .unwrap(),
    )
    .unwrap();

    assert_eq!(result["endpoints"]["base"], format!("tree:{base}"));
    assert_eq!(result["endpoints"]["target"], "worktree");
    assert!(deleted(&result, "SnapshotBase").is_some(), "{result}");
    assert!(introduced(&result, "LiveNow").is_some(), "{result}");
}

#[test]
fn analyze_diff_snapshot_untracked_edit_delete_add_rename_and_binary() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
    fs::write(
        root.join("tracked.go"),
        "package sample\nfunc Tracked() {}\n",
    )
    .unwrap();
    commit(root, "head");
    let objects = temp.path().join("objects");
    // `old.go` and `new.go` share byte-identical content so rename detection
    // fires on exactly that pair. The deleted and added files are deliberately
    // dissimilar: with near-identical one-line bodies git's similarity
    // heuristic pairs them as a rename too, which would hide the add/delete
    // statuses this test exists to prove.
    let base = alternate_tree_entries(
        root,
        &objects,
        &[
            ("edit.go", b"package sample\nfunc BeforeEdit() {}\n"),
            (
                "delete.go",
                b"package sample\n\nfunc DeletedUntracked() string {\n\treturn \"gone after the turn\"\n}\n",
            ),
            ("old.go", b"package sample\nfunc Renamed() {}\n"),
        ],
    );
    let target = alternate_tree_entries(
        root,
        &objects,
        &[
            ("edit.go", b"package sample\nfunc AfterEdit() {}\n"),
            ("new.go", b"package sample\nfunc Renamed() {}\n"),
            (
                "added.go",
                b"package sample\n\nimport \"strings\"\n\nfunc Added(parts []string) int {\n\tjoined := strings.Join(parts, \",\")\n\treturn len(joined)\n}\n",
            ),
            ("asset.bin", b"\0binary\0changed"),
        ],
    );
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .unwrap()
        .with_diff_snapshot_object_dir(objects);
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": base, "target": target}).to_string(),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(deleted(&result, "DeletedUntracked").is_some());
    assert!(deleted(&result, "BeforeEdit").is_some());
    assert!(introduced(&result, "AfterEdit").is_some());
    assert!(
        result["file_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["old_path"] == "old.go"
                && c["path"] == "new.go"
                && c["status"] == "renamed")
    );
    assert!(
        patch_array(&result, "/patch_symbols/moved")
            .iter()
            .any(|moved| {
                moved["before"]["path"] == "old.go"
                    && moved["after"]["name"] == "Renamed"
                    && moved["after"]["path"] == "new.go"
            }),
        "{result}"
    );
    assert!(
        result["file_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["path"] == "added.go" && c["status"] == "added"),
        "{result}"
    );
    assert!(introduced(&result, "Added").is_some(), "{result}");
    let asset = file_change(&result, "asset.bin");
    assert_eq!(asset["is_parseable"], false);
    // Git reports binary content as `-  -` in numstat because it emits no line
    // hunks; the flag carries that, and the counts stay 0 rather than guessing.
    assert_eq!(asset["is_binary"], true, "{result}");
    assert_eq!(asset["insertions"], 0);
    assert_eq!(asset["deletions"], 0);
    assert_eq!(
        file_change(&result, "added.go")["is_binary"],
        false,
        "a text file added alongside binary content is not binary: {result}"
    );
}

/// `insertions` and `deletions` are `git diff --numstat`, so pin them against
/// the real thing over a patch holding every shape at once: an edit, a
/// deletion, an addition, a pure rename and a binary file. The numstat text is
/// asserted first so a change in Git's own accounting is visible here rather
/// than silently redefining the field.
#[test]
fn analyze_diff_file_counts_match_git_numstat() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    init_repo(root, None);
    fs::write(
        root.join("edit.go"),
        "package sample\n\nfunc Edited() int {\n\treturn 1\n}\n",
    )
    .unwrap();
    // Deliberately unlike `added.go` below: two near-identical one-line bodies
    // get paired as a rename by similarity detection, which would replace the
    // separate add and delete this test is here to count.
    fs::write(
        root.join("gone.go"),
        concat!(
            "package sample\n",
            "\n",
            "func Gone() string {\n",
            "\tfirst := \"this whole file disappears\"\n",
            "\tsecond := \" across several distinct lines\"\n",
            "\treturn first + second\n",
            "}\n",
        ),
    )
    .unwrap();
    fs::write(
        root.join("old.go"),
        "package sample\n\nfunc Renamed() int {\n\treturn 7\n}\n",
    )
    .unwrap();
    // A NUL byte early in the content is what makes Git call it binary. This
    // one is committed at both endpoints so the modified-binary case is covered
    // alongside the added one; both must reach `is_binary` through the flag the
    // patch walk sees rather than through any line count.
    fs::write(root.join("existing.bin"), b"\0binary\0before\0").unwrap();
    let base = commit(root, "base");

    // One replaced line plus one added line, so insertions and deletions differ.
    fs::write(
        root.join("edit.go"),
        "package sample\n\nfunc Edited() int {\n\tx := 2\n\treturn x\n}\n",
    )
    .unwrap();
    fs::remove_file(root.join("gone.go")).unwrap();
    git(root, &["mv", "old.go", "new.go"]);
    fs::write(
        root.join("added.go"),
        concat!(
            "package sample\n",
            "\n",
            "import \"strings\"\n",
            "\n",
            "func Added(parts []string) int {\n",
            "\tjoined := strings.Join(parts, \",\")\n",
            "\treturn len(joined)\n",
            "}\n",
        ),
    )
    .unwrap();
    fs::write(root.join("asset.bin"), b"\0binary\0payload\0").unwrap();
    fs::write(root.join("existing.bin"), b"\0binary\0after\0\0more\0").unwrap();
    let target = commit(root, "every shape at once");

    assert_eq!(
        git_output(root, &["diff", "--numstat", &base, &target]),
        concat!(
            "8\t0\tadded.go\n",
            "-\t-\tasset.bin\n",
            "2\t1\tedit.go\n",
            "-\t-\texisting.bin\n",
            "0\t7\tgone.go\n",
            "0\t0\told.go => new.go"
        ),
        "fixture must keep producing every numstat shape"
    );

    let result = analyze(root, serde_json::json!({"base": base, "target": target}));
    let counts = |path: &str| {
        let change = file_change(&result, path);
        (
            change["insertions"].as_u64().unwrap(),
            change["deletions"].as_u64().unwrap(),
            change["is_binary"].as_bool().unwrap(),
        )
    };
    assert_eq!(counts("asset.bin"), (0, 0, true), "added binary: {result}");
    assert_eq!(
        counts("existing.bin"),
        (0, 0, true),
        "modified binary: {result}"
    );
    assert_eq!(counts("added.go"), (8, 0, false), "{result}");
    assert_eq!(counts("edit.go"), (2, 1, false), "{result}");
    assert_eq!(counts("gone.go"), (0, 7, false), "{result}");
    assert_eq!(counts("new.go"), (0, 0, false), "{result}");
    assert_eq!(file_change(&result, "new.go")["old_path"], "old.go");
}

#[test]
fn analyze_diff_rejects_blob_endpoints_and_keeps_commits_available_with_alternate() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    // The revision loop below resolves the branch by name, so pin the initial
    // branch instead of inheriting the host's `init.defaultBranch`.
    init_repo(root, Some("master"));
    fs::write(root.join("lib.go"), "package sample\nfunc Old() {}\n").unwrap();
    let first = commit(root, "first");
    fs::write(root.join("lib.go"), "package sample\nfunc New() {}\n").unwrap();
    let second = commit(root, "second");
    let blob = git_output(root, &["hash-object", "lib.go"]);
    let objects = temp.path().join("objects");
    fs::create_dir(&objects).unwrap();
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .unwrap()
        .with_diff_snapshot_object_dir(objects);
    for args in [
        serde_json::json!({"base": blob, "target": second}),
        serde_json::json!({"base": first, "target": blob}),
    ] {
        let error = service
            .call_tool_json("analyze_diff", &args.to_string())
            .unwrap_err();
        assert!(error.message.contains("a blob"));
        assert!(error.message.contains("commit or tree"));
    }
    for (base, target) in [
        ("HEAD~1", "HEAD"),
        ("HEAD~1", "master"),
        (&first[..8], &second[..8]),
    ] {
        let result: Value = serde_json::from_str(
            &service
                .call_tool_json(
                    "analyze_diff",
                    &serde_json::json!({"base": base, "target": target}).to_string(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result["endpoints"]["base"], first);
        assert_eq!(result["endpoints"]["target"], second);
    }
}

#[test]
fn analyze_diff_large_snapshot_interval_keeps_structured_result() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
    fs::write(root.join("seed.go"), "package sample\nfunc Seed() {}\n").unwrap();
    commit(root, "head");
    let objects = temp.path().join("objects");
    let before = "package sample\nfunc LargeBefore() {}\n";
    // The postimage must both exceed prompt truncation limits (thousands of
    // changed lines) and push a single callee past the usage-graph callsite
    // cap, so the truncation notice is exercised rather than merely present.
    let after = format!(
        "package sample\n\
         func Target() {{}}\n\
         func Caller() {{\n{}}}\n\
         {}func LargeAfter() {{}}\n",
        "\tTarget()\n".repeat(CALLSITES_ABOVE_CAP),
        "// deliberately large interval\n".repeat(4_000)
    );
    let base = alternate_tree(root, &objects, "large.go", before);
    let target = alternate_tree(root, &objects, "large.go", &after);
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .unwrap()
        .with_diff_snapshot_object_dir(objects);
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_diff",
                &serde_json::json!({"base": base, "target": target}).to_string(),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(introduced(&result, "LargeAfter").is_some());
    let truncated = result["large_callsite_symbols"]
        .as_array()
        .expect("large_callsite_symbols array");
    let target_notice = truncated
        .iter()
        .find(|symbol| {
            symbol["fqn"]
                .as_str()
                .is_some_and(|fqn| fqn.contains("Target"))
        })
        .unwrap_or_else(|| panic!("expected a large-callsite notice for Target: {result}"));
    let limit = target_notice["limit"].as_u64().expect("limit");
    let total = target_notice["total_callsites"].as_u64().expect("total");
    assert!(
        total > limit,
        "truncation notice must report more callsites than the limit: {target_notice}"
    );
    assert!(
        total >= CALLSITES_ABOVE_CAP as u64,
        "every generated callsite should be counted: {target_notice}"
    );
}
