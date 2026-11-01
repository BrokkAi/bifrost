use super::{
    HistoryRankingStatus, most_important_project_files_with_cancellation,
    most_relevant_project_files_history_only, spawn_commit_history_warm,
};
use crate::language_test_support::java_analyzer;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::test_support::write_file;
use git2::{Repository, Signature};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn commit_paths(repo: &Repository, add: &[&str], remove: &[&str]) {
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    brokk_bifrost_analysis::test_support::shared_git::commit_paths_with_removals(
        repo, add, remove, "history", &signature,
    );
}

fn file(root: &Path, name: &str) -> ProjectFile {
    ProjectFile::new(root.to_path_buf(), name)
}

#[test]
fn completed_history_warm_includes_oldest_cochange_at_window_limit() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "Seed.java", "class Seed { int version = 0; }");
    write_file(root, "OldPeer.java", "class OldPeer {}");
    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, &["Seed.java", "OldPeer.java"], &[]);
    for version in 1..1000 {
        write_file(
            root,
            "Seed.java",
            &format!("class Seed {{ int version = {version}; }}"),
        );
        commit_paths(&repo, &["Seed.java"], &[]);
    }

    spawn_commit_history_warm(root.to_path_buf())
        .unwrap()
        .join()
        .unwrap();
    let analyzer = java_analyzer(root);
    let peer = file(root, "OldPeer.java");
    let (ranked, status) = most_important_project_files_with_cancellation(
        &analyzer,
        &[file(root, "Seed.java"), peer.clone()],
        2,
        Some(&CancellationToken::default()),
    );
    assert_eq!(status, HistoryRankingStatus::Complete);
    assert!(
        ranked.contains(&peer),
        "complete history omitted {peer:?}: {ranked:?}"
    );
}

#[test]
fn shallow_boundary_uses_locally_available_cochange_history() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("source");
    let clone = temp.path().join("clone");
    std::fs::create_dir(&source).unwrap();
    write_file(&source, "Seed.java", "class Seed { int version = 0; }");
    write_file(&source, "Peer.java", "class Peer { int version = 0; }");
    let repo = Repository::init(&source).unwrap();
    commit_paths(&repo, &["Seed.java", "Peer.java"], &[]);
    write_file(&source, "Seed.java", "class Seed { int version = 1; }");
    write_file(&source, "Peer.java", "class Peer { int version = 1; }");
    commit_paths(&repo, &["Seed.java", "Peer.java"], &[]);
    write_file(&source, "Seed.java", "class Seed { int version = 2; }");
    commit_paths(&repo, &["Seed.java"], &[]);

    let status = Command::new("git")
        .arg("clone")
        .args(["--quiet", "--no-local", "--depth", "2"])
        .arg(&source)
        .arg(&clone)
        .status()
        .unwrap();
    assert!(status.success());

    let analyzer = java_analyzer(&clone);
    let peer = file(&clone, "Peer.java");
    let (ranked, history_status) = most_relevant_project_files_history_only(
        &analyzer,
        &[(file(&clone, "Seed.java"), 1.0)],
        5,
        None,
        &CancellationToken::default(),
    );
    assert_eq!(history_status, HistoryRankingStatus::Complete);
    assert!(
        ranked.contains(&peer),
        "shallow cochange lost {peer:?}: {ranked:?}"
    );
}

#[test]
fn malformed_promisor_setting_refuses_history_walk() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "Seed.java", "class Seed {}");
    write_file(root, "Peer.java", "class Peer {}");
    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, &["Seed.java", "Peer.java"], &[]);
    write_file(root, "Seed.java", "class Seed { int value = 1; }");
    write_file(root, "Peer.java", "class Peer { int value = 1; }");
    commit_paths(&repo, &["Seed.java", "Peer.java"], &[]);
    let mut config = repo.config().unwrap();
    config
        .set_str("remote.origin.url", "https://example.invalid/repo")
        .unwrap();
    config
        .set_str("remote.origin.promisor", "not-a-boolean")
        .unwrap();

    let analyzer = java_analyzer(root);
    let (ranked, status) = most_relevant_project_files_history_only(
        &analyzer,
        &[(file(root, "Seed.java"), 1.0)],
        5,
        None,
        &CancellationToken::default(),
    );
    assert_eq!(status, HistoryRankingStatus::HistoryUnavailable);
    assert!(ranked.is_empty());
}

#[test]
fn merge_rename_follows_first_parent_history() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "Seed.java", "class Seed { int value = 0; }");
    write_file(root, "old/Item.java", "class Item { int value = 0; }");
    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, &["Seed.java", "old/Item.java"], &[]);

    let checkout_feature = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["checkout", "-q", "-b", "feature"])
        .status()
        .unwrap();
    assert!(checkout_feature.success());
    std::fs::create_dir(root.join("new")).unwrap();
    std::fs::rename(root.join("old/Item.java"), root.join("new/Item.java")).unwrap();
    commit_paths(&repo, &["new/Item.java"], &["old/Item.java"]);

    let checkout_main = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["checkout", "-q", "-"])
        .status()
        .unwrap();
    assert!(checkout_main.success());
    write_file(root, "Seed.java", "class Seed { int value = 1; }");
    let main_repo = Repository::open(root).unwrap();
    commit_paths(&main_repo, &["Seed.java"], &[]);
    let merge = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgSign=false",
            "merge",
            "--quiet",
            "--no-ff",
            "feature",
            "-m",
            "merge feature",
        ])
        .status()
        .unwrap();
    assert!(merge.success());

    let analyzer = java_analyzer(root);
    let current = file(root, "new/Item.java");
    let (ranked, status) = most_relevant_project_files_history_only(
        &analyzer,
        &[(file(root, "Seed.java"), 1.0)],
        5,
        None,
        &CancellationToken::default(),
    );
    assert_eq!(status, HistoryRankingStatus::Complete);
    assert!(
        ranked.contains(&current),
        "first-parent lineage lost {current:?}: {ranked:?}"
    );
}

#[cfg(unix)]
#[test]
fn type_change_contributes_to_current_history_window() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "Seed.java", "class Seed { int version = 0; }");
    write_file(root, "Peer.java", "class Peer {}");
    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, &["Seed.java", "Peer.java"], &[]);
    for version in 1..1001 {
        write_file(
            root,
            "Seed.java",
            &format!("class Seed {{ int version = {version}; }}"),
        );
        commit_paths(&repo, &["Seed.java"], &[]);
    }
    std::fs::remove_file(root.join("Peer.java")).unwrap();
    std::os::unix::fs::symlink("Seed.java", root.join("Peer.java")).unwrap();
    write_file(root, "Seed.java", "class Seed { int version = 1001; }");
    commit_paths(&repo, &["Seed.java", "Peer.java"], &[]);

    let analyzer = java_analyzer(root);
    let peer = file(root, "Peer.java");
    let (ranked, status) = most_important_project_files_with_cancellation(
        &analyzer,
        &[file(root, "Seed.java"), peer.clone()],
        2,
        None,
    );
    assert_eq!(status, HistoryRankingStatus::Complete);
    assert!(
        ranked.contains(&peer),
        "type-change history lost {peer:?}: {ranked:?}"
    );
}

fn rename_history_ranks_current_file(
    old_name: &str,
    new_name: &str,
    old_content: &str,
    new_content: &str,
) -> bool {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "Seed.java", "class Seed { int value = 0; }");
    write_file(root, old_name, old_content);
    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, &["Seed.java", old_name], &[]);
    write_file(root, "Seed.java", "class Seed { int value = 1; }");
    commit_paths(&repo, &["Seed.java"], &[]);
    std::fs::create_dir_all(root.join(new_name).parent().unwrap()).unwrap();
    std::fs::rename(root.join(old_name), root.join(new_name)).unwrap();
    write_file(root, new_name, new_content);
    commit_paths(&repo, &[new_name], &[old_name]);

    let rename_status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff-tree", "-r", "--name-status", "-M50", "HEAD^", "HEAD"])
        .output()
        .unwrap();
    assert!(rename_status.status.success());
    assert!(
        rename_status.stdout.starts_with(b"R"),
        "fixture must contain a Git rename: {:?}",
        String::from_utf8_lossy(&rename_status.stdout)
    );

    let analyzer = java_analyzer(root);
    let (ranked, status) = most_relevant_project_files_history_only(
        &analyzer,
        &[(file(root, "Seed.java"), 1.0)],
        5,
        None,
        &CancellationToken::default(),
    );
    assert_eq!(status, HistoryRankingStatus::Complete);
    ranked.contains(&file(root, new_name))
}

#[test]
fn digit_bearing_stems_do_not_transfer_history() {
    assert!(!rename_history_ranks_current_file(
        "Worker2.java",
        "Worker3.java",
        "class Worker { int value = 1; }",
        "class Worker { int value = 1; }",
    ));
}

#[test]
fn dotted_stems_do_not_transfer_history() {
    assert!(!rename_history_ranks_current_file(
        "a.b.java",
        "a.c.java",
        "class Worker { int value = 1; }",
        "class Worker { int value = 1; }",
    ));
}

#[test]
fn accepted_rename_transfers_old_cochange_to_current_file() {
    assert!(rename_history_ranks_current_file(
        "old/Item.java",
        "new/Item.java",
        "class Item { int value = 1; }",
        "class Item { int value = 1; }",
    ));
}

#[test]
fn short_subset_does_not_inherit_longer_file_history() {
    let common = (0..20)
        .map(|index| format!("    int field{index};\n"))
        .collect::<String>();
    let old_content = format!(
        "class Item {{\n{common}    int extra_one, extra_two, extra_three, extra_four;\n}}\n"
    );
    let new_content = format!("class Item {{\n{common}}}\n");
    assert!(!rename_history_ranks_current_file(
        "old/Item.java",
        "new/Item.java",
        &old_content,
        &new_content,
    ));
}

#[test]
fn case_only_identifier_changes_preserve_safe_lineage() {
    let old_fields = (0..12)
        .map(|index| format!("    int field{index};\n"))
        .collect::<String>();
    let new_fields = (0..12)
        .map(|index| match index {
            0 | 1 => format!("    int FIELD{index};\n"),
            _ => format!("    int field{index};\n"),
        })
        .collect::<String>();
    let old_content = format!("class Item {{\n{old_fields}}}\n");
    let new_content = format!("class Item {{\n{new_fields}}}\n");
    assert!(rename_history_ranks_current_file(
        "old/Item.java",
        "new/Item.java",
        &old_content,
        &new_content,
    ));
}

#[test]
fn one_character_tokens_can_certify_safe_lineage() {
    let fields = ('a'..='z')
        .map(|name| format!("    int {name};\n"))
        .collect::<String>();
    let old_content = format!("class OldContainer {{\n{fields}}}\n");
    let new_content = format!("class NewContainer {{\n{fields}}}\n");
    assert!(rename_history_ranks_current_file(
        "old/Item.java",
        "new/Item.java",
        &old_content,
        &new_content,
    ));
}
