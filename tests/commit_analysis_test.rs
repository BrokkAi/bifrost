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

fn patch_array<'a>(result: &'a Value, pointer: &str) -> &'a Vec<Value> {
    result
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array at {pointer}: {result}"))
}

fn find_symbol<'a>(symbols: &'a [Value], name: &str) -> Option<&'a Value> {
    symbols
        .iter()
        .find(|symbol| symbol["name"].as_str() == Some(name))
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
        result.get("introduced_symbols").is_none(),
        "old top-level introduced_symbols field should be removed"
    );
    assert!(
        result.get("edited_symbols").is_none(),
        "old top-level edited_symbols field should be removed"
    );
    assert!(
        result.get("deleted_symbols").is_none(),
        "old top-level deleted_symbols field should be removed"
    );

    let preimage_edited = patch_array(&result, "/patch_symbols/preimage/edited");
    let postimage_edited = patch_array(&result, "/patch_symbols/postimage/edited");
    let postimage_introduced = patch_array(&result, "/patch_symbols/postimage/introduced");

    let old_existing = find_symbol(preimage_edited, "Existing").expect("old Existing touched");
    assert!(old_existing["fqn"].as_str().unwrap().ends_with("Existing"));
    assert_eq!(old_existing["path"], "lib.go");
    assert_eq!(old_existing["touched_old_lines"], serde_json::json!([4]));
    assert_eq!(old_existing["touched_new_lines"], serde_json::json!([]));
    assert_eq!(old_existing["change_reason"], "old_hunk_overlap");

    let new_existing = find_symbol(postimage_edited, "Existing").expect("new Existing touched");
    assert!(new_existing["fqn"].as_str().unwrap().ends_with("Existing"));
    assert_eq!(new_existing["path"], "lib.go");
    assert_eq!(new_existing["touched_old_lines"], serde_json::json!([]));
    assert_eq!(new_existing["touched_new_lines"], serde_json::json!([6, 7]));
    assert_eq!(new_existing["change_reason"], "new_hunk_overlap");

    let added = find_symbol(postimage_introduced, "Added").expect("Added introduced");
    assert!(added["fqn"].as_str().unwrap().ends_with("Added"));
    assert_eq!(added["path"], "lib.go");
    assert_eq!(added["touched_old_lines"], serde_json::json!([]));
    assert_eq!(added["change_reason"], "new_hunk_overlap");

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

#[test]
fn analyze_commit_reads_from_bare_repo_without_worktree() {
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

    let service = SearchToolsService::new_without_semantic_index(bare).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_commit",
                &serde_json::json!({"revision": head}).to_string(),
            )
            .expect("analyze_commit"),
    )
    .expect("json");

    assert_eq!(result["commit"]["hash"].as_str().unwrap(), head);
    assert!(
        patch_array(&result, "/patch_symbols/postimage/introduced")
            .iter()
            .any(|symbol| symbol["name"] == "B" && symbol["fqn"].as_str().unwrap().ends_with("B"))
    );
}

#[test]
fn analyze_commit_from_python_service_does_not_build_root_workspace_cache() {
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
                "analyze_commit",
                &serde_json::json!({"revision": head}).to_string(),
            )
            .expect("analyze_commit"),
    )
    .expect("json");

    assert_eq!(result["commit"]["hash"].as_str().unwrap(), head);
    assert!(
        !root.join(".bifrost").join("analyzer.db").exists(),
        "analyze_commit should not force the root workspace analyzer/cache"
    );
    assert!(
        !root.join(".brokk").join("bifrost_cache.db").exists(),
        "analyze_commit should honor FileSetProject's persistence opt-out"
    );
}

#[test]
fn analyze_commit_reports_renamed_file_touches_on_exact_image_paths() {
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
                "analyze_commit",
                &serde_json::json!({"revision": head}).to_string(),
            )
            .expect("analyze_commit"),
    )
    .expect("json");

    let preimage_edited = patch_array(&result, "/patch_symbols/preimage/edited");
    let postimage_edited = patch_array(&result, "/patch_symbols/postimage/edited");

    let old_keep = find_symbol(preimage_edited, "Keep").expect("old Keep touched");
    assert_eq!(old_keep["path"], "old.go");
    assert_eq!(old_keep["touched_old_lines"], serde_json::json!([4]));
    assert_eq!(old_keep["touched_new_lines"], serde_json::json!([]));

    let new_keep = find_symbol(postimage_edited, "Keep").expect("new Keep touched");
    assert_eq!(new_keep["path"], "new.go");
    assert_eq!(new_keep["touched_old_lines"], serde_json::json!([]));
    assert_eq!(new_keep["touched_new_lines"], serde_json::json!([4]));
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

/// Issue #1102 (commit-analysis half): with `include_tests:false`, symbol
/// filtering is per declaration, not whole-file. A Rust file that adds both a
/// production function and an inline `#[cfg(test)] mod tests` must report the
/// production symbol as introduced while suppressing the inline test symbol.
/// Before the fix, the whole file was gated on `contains_tests`, so the
/// production symbol was suppressed too.
#[test]
fn analyze_commit_filters_test_symbols_per_declaration_not_whole_file() {
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
                "analyze_commit",
                &serde_json::json!({"revision": head, "include_tests": false}).to_string(),
            )
            .expect("analyze_commit"),
    )
    .expect("json");

    let introduced = patch_array(&result, "/patch_symbols/postimage/introduced");
    assert!(
        find_symbol(introduced, "make_widget").is_some(),
        "production symbol should be introduced with include_tests:false: {result}"
    );
    assert!(
        find_symbol(introduced, "it_works").is_none(),
        "inline test symbol must be filtered with include_tests:false: {result}"
    );
}
