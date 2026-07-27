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
    assert!(
        result.get("commit").is_none(),
        "old `commit` endpoint pair should be removed"
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

    let service = SearchToolsService::new_without_semantic_index(bare).expect("service");
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
        patch_array(&result, "/patch_symbols/postimage/introduced")
            .iter()
            .any(|symbol| symbol["name"] == "B" && symbol["fqn"].as_str().unwrap().ends_with("B"))
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
        !root.join(".bifrost").join("bifrost_cache.db").exists(),
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

    let postimage_edited = patch_array(&result, "/patch_symbols/postimage/edited");
    let postimage_introduced = patch_array(&result, "/patch_symbols/postimage/introduced");
    assert!(
        find_symbol(postimage_edited, "Existing").is_some(),
        "uncommitted edit to a tracked file should surface: {result}"
    );
    assert!(
        find_symbol(postimage_introduced, "Fresh").is_some(),
        "untracked new file should surface as introduced: {result}"
    );
    assert!(
        find_symbol(postimage_edited, "Untouched").is_none()
            && find_symbol(postimage_introduced, "Untouched").is_none(),
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

    let introduced = patch_array(&result, "/patch_symbols/postimage/introduced");
    assert!(
        find_symbol(introduced, "Committed").is_some(),
        "committed change since base should surface: {result}"
    );
    assert!(
        find_symbol(introduced, "Uncommitted").is_some(),
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

    let introduced = patch_array(&result, "/patch_symbols/postimage/introduced");
    assert!(
        find_symbol(introduced, "Durable").is_some(),
        "symbol added in B and kept in C should surface: {result}"
    );
    assert!(
        find_symbol(introduced, "Transient").is_none(),
        "symbol added in B and reverted in C must not surface: {result}"
    );
    assert!(
        patch_array(&result, "/patch_symbols/preimage/deleted")
            .iter()
            .all(|symbol| symbol["name"] != "Transient"),
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
        find_symbol(
            patch_array(&result, "/patch_symbols/postimage/introduced"),
            "Other"
        )
        .is_some(),
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
        !root.join(".bifrost").join("bifrost_cache.db").exists(),
        "worktree-endpoint analyzer must stay ephemeral over the live project root"
    );
    assert!(
        !root.join(".bifrost").join("analyzer.db").exists(),
        "analyze_diff should not force the root workspace analyzer/cache"
    );
}
