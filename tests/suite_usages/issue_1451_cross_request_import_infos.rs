//! #1451: per-file import infos are retained across requests, so a warm scan
//! stops re-hydrating the same file's imports from SQLite once per reference.
//!
//! The retained entries are keyed by blob oid, so this suite's job is to prove
//! the keying rather than the speedup: rewriting a file's `use` declaration
//! must resolve to a *new* key, and the very next scan must resolve the call
//! through the *new* import. A cache keyed by path -- or one carrying any
//! stale-content path at all -- keeps reporting the old module's hit here.

use brokk_bifrost::SearchToolsService;
use git2::{Repository, Signature};
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const CALLERS: &str = "src/callers.rs";

/// `collect_it` is declared in both `target` and `decoy`. Which declaration a
/// bare `collect_it(..)` call resolves to is decided purely by this file's
/// import binder, which is what `import_info_of` feeds.
const CALLERS_IMPORTING_TARGET: &str = concat!(
    "use crate::target::collect_it;\n",
    "\n",
    "pub fn direct() -> i32 {\n",
    "    collect_it(1)\n",
    "}\n",
);

const CALLERS_IMPORTING_DECOY: &str = concat!(
    "use crate::decoy::collect_it;\n",
    "\n",
    "pub fn direct() -> i32 {\n",
    "    collect_it(1)\n",
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
            "[package]\nname = \"importreq\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod target;\npub mod decoy;\npub mod callers;\n",
        ),
        (
            "src/target.rs",
            "pub fn collect_it(value: i32) -> i32 {\n    value\n}\n",
        ),
        (
            "src/decoy.rs",
            "pub fn collect_it(value: i32) -> i32 {\n    value + 1\n}\n",
        ),
        (CALLERS, CALLERS_IMPORTING_TARGET),
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

/// Usages of the `collect_it` declared in the named module file.
fn scan_declaration_in(service: &SearchToolsService, module: &str) -> Value {
    let arguments = format!(
        r#"{{"targets":[{{"path":"src/{module}.rs","line":1,"column":8}}],"include_tests":true}}"#
    );
    let payload = service
        .call_tool_json("scan_usages_by_location", &arguments)
        .expect("scan_usages_by_location call failed");
    serde_json::from_str(&payload).expect("scan_usages_by_location returned invalid JSON")
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
fn a_rewritten_import_is_rehydrated_rather_than_served_from_the_retained_infos() {
    let temp = committed_repo();
    let service = SearchToolsService::new_manual_without_semantic_index(temp.path().to_path_buf())
        .expect("searchtools service");

    let target_before = scan_declaration_in(&service, "target");
    assert_eq!(
        vec![4],
        caller_lines(&target_before),
        "the call must resolve through the target import; payload: {target_before:#}"
    );
    let decoy_before = scan_declaration_in(&service, "decoy");
    assert!(
        caller_lines(&decoy_before).is_empty(),
        "nothing imports decoy yet; payload: {decoy_before:#}"
    );

    fs::write(temp.path().join(CALLERS), CALLERS_IMPORTING_DECOY).expect("rewrite callers");
    service
        .call_tool_json("update_paths", r#"{"paths":["src/callers.rs"]}"#)
        .expect("update_paths call failed");

    // Both scans run against the same analyzer instance, and therefore the same
    // retained import infos, as the two above.
    let decoy_after = scan_declaration_in(&service, "decoy");
    assert_eq!(
        vec![4],
        caller_lines(&decoy_after),
        "the rewritten import must move the call to decoy; payload: {decoy_after:#}"
    );
    let target_after = scan_declaration_in(&service, "target");
    assert!(
        caller_lines(&target_after).is_empty(),
        "the stale target import must not survive the rewrite; payload: {target_after:#}"
    );
}
