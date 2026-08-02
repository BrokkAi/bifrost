//! #1450: prepared syntax trees are retained across requests, so a warm scan
//! stops re-parsing candidates a previous request already parsed.
//!
//! The retained entries are keyed by blob oid, so this suite's job is to prove
//! the keying rather than the speedup: an edited file must resolve to a *new*
//! key and its new usage site must appear on the very next scan. A cache keyed
//! by path -- or one carrying any stale-content path at all -- fails the second
//! assertion here while passing the first.

use brokk_bifrost::SearchToolsService;
use git2::{Repository, Signature};
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const CALLERS: &str = "src/callers.rs";

const CALLERS_BEFORE: &str = concat!(
    "use crate::target::collect_it;\n",
    "\n",
    "pub fn direct() -> i32 {\n",
    "    collect_it(1)\n",
    "}\n",
);

/// Same prefix, one extra call site: the scan must report both lines once the
/// session is told the file changed.
const CALLERS_AFTER: &str = concat!(
    "use crate::target::collect_it;\n",
    "\n",
    "pub fn direct() -> i32 {\n",
    "    collect_it(1)\n",
    "}\n",
    "\n",
    "pub fn added_later() -> i32 {\n",
    "    collect_it(2)\n",
    "}\n",
);

/// A committed git repo, not a bare temp dir: outside one, live paths are
/// treated as overlays whose oid is trusted without re-stat, which would make
/// the edit visible for the wrong reason.
fn committed_repo() -> TempDir {
    let temp = TempDir::new().expect("temp dir");
    let repo = Repository::init(temp.path()).expect("git init");
    {
        let mut config = repo.config().expect("git config");
        config
            .set_str("user.email", "t@example.com")
            .expect("email");
        config.set_str("user.name", "T").expect("name");
    }
    let files = [
        (
            "Cargo.toml",
            "[package]\nname = \"crossreq\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        ),
        ("src/lib.rs", "pub mod target;\npub mod callers;\n"),
        (
            "src/target.rs",
            "pub fn collect_it(value: i32) -> i32 {\n    value\n}\n",
        ),
        (CALLERS, CALLERS_BEFORE),
    ];
    let mut index = repo.index().expect("git index");
    for (rel, contents) in files {
        let path = temp.path().join(rel);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture dir");
        fs::write(&path, contents).expect("fixture write");
        index.add_path(Path::new(rel)).expect("git add");
    }
    index.write().expect("git index write");
    let tree = repo
        .find_tree(index.write_tree().expect("git write tree"))
        .expect("git tree");
    let signature = Signature::now("T", "t@example.com").expect("git signature");
    repo.commit(Some("HEAD"), &signature, &signature, "init", &tree, &[])
        .expect("git commit");
    temp
}

fn scan(service: &SearchToolsService) -> Value {
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["collect_it"],"include_tests":true}"#,
        )
        .expect("scan_usages_by_reference call failed");
    serde_json::from_str(&payload).expect("scan_usages_by_reference returned invalid JSON")
}

/// Lines the scan reported inside `src/callers.rs`.
fn caller_lines(value: &Value) -> Vec<u64> {
    let mut lines = Vec::new();
    for entry in value["results"].as_array().into_iter().flatten() {
        for group in entry["files"].as_array().into_iter().flatten() {
            let path = group["path"].as_str().unwrap_or_default();
            if !path.ends_with("callers.rs") {
                continue;
            }
            for hit in group["hits"].as_array().into_iter().flatten() {
                lines.push(hit["line"].as_u64().expect("hit carries a line"));
            }
        }
    }
    lines.sort_unstable();
    lines
}

#[test]
fn an_edited_file_is_rescanned_rather_than_served_from_the_retained_tree() {
    let temp = committed_repo();
    let service = SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
        .expect("searchtools service");

    let before = scan(&service);
    assert_eq!(
        vec![4],
        caller_lines(&before),
        "baseline call site; payload: {before:#}"
    );

    fs::write(temp.path().join(CALLERS), CALLERS_AFTER).expect("rewrite callers");
    service
        .call_tool_json("update_paths", r#"{"paths":["src/callers.rs"]}"#)
        .expect("update_paths call failed");

    // The second scan runs against the same analyzer instance, and therefore
    // the same retained prepared trees, as the first.
    let after = scan(&service);
    assert_eq!(
        vec![4, 8],
        caller_lines(&after),
        "the call site added at callers.rs:8 must appear; payload: {after:#}"
    );
}
