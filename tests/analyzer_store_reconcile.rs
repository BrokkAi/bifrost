mod common;

use brokk_bifrost::analyzer::store::{AnalyzerStore, analyzer_db_path};
use brokk_bifrost::analyzer::{BuildProgressEvent, BuildProgressPhase};
use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use common::InlineTestProject;
use git2::build::CheckoutBuilder;
use git2::{IndexAddOption, ObjectType, Oid, Repository, Signature};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn init_repo(root: &Path) -> Repository {
    let repo = Repository::init(root).unwrap();
    {
        let mut config = repo.config().unwrap();
        config.set_str("user.email", "t@example.com").unwrap();
        config.set_str("user.name", "T").unwrap();
        // These tests assert parse reuse across branch switches and linked
        // worktrees. Keep checkout bytes identical to the written fixture bytes
        // so the working-tree-byte cache key is stable on Windows too.
        config.set_str("core.autocrlf", "false").unwrap();
    }
    repo
}

fn commit_all(repo: &Repository, message: &str) -> Oid {
    let mut index = repo.index().unwrap();
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .unwrap();
    commit_index(repo, index, message)
}

fn commit_paths(repo: &Repository, paths: &[&str], message: &str) -> Oid {
    let mut index = repo.index().unwrap();
    for path in paths {
        index.add_path(Path::new(path)).unwrap();
    }
    commit_index(repo, index, message)
}

fn commit_index(repo: &Repository, mut index: git2::Index, message: &str) -> Oid {
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("T", "t@example.com").unwrap();
    let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
    match parent {
        Some(parent) => repo
            .commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent])
            .unwrap(),
        None => repo
            .commit(Some("HEAD"), &sig, &sig, message, &tree, &[])
            .unwrap(),
    }
}

fn checkout(repo: &Repository, refname: &str) {
    repo.set_head(refname).unwrap();
    repo.checkout_head(Some(CheckoutBuilder::new().force()))
        .unwrap();
}

fn build_with_parse_count(project: Arc<dyn Project>) -> (WorkspaceAnalyzer, usize) {
    let parses = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&parses);
    let analyzer =
        WorkspaceAnalyzer::build_persisted_with_progress(project, AnalyzerConfig::default(), {
            move |event: BuildProgressEvent| {
                if event.phase == BuildProgressPhase::Parse {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    (analyzer, parses.load(Ordering::Relaxed))
}

#[test]
fn branch_switch_reuses_seen_blob_parse_results() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repo = init_repo(&root);
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(root.join("pkg/a.py"), "class A:\n    pass\n").unwrap();
    std::fs::write(root.join("pkg/b.py"), "class B:\n    pass\n").unwrap();
    commit_all(&repo, "a");
    let main_ref = repo.head().unwrap().name().unwrap().to_string();

    let project = Arc::new(TestProject::new(root.clone(), Language::Python));
    let (_, initial_parses) = build_with_parse_count(project.clone());
    assert_eq!(initial_parses, 2);

    let head = repo.head().unwrap().peel_to_commit().unwrap();
    repo.branch("branch-b", &head, false).unwrap();
    checkout(&repo, "refs/heads/branch-b");
    std::fs::write(root.join("pkg/a.py"), "class A2:\n    pass\n").unwrap();
    commit_paths(&repo, &["pkg/a.py"], "b");

    let (_, branch_parses) = build_with_parse_count(project.clone());
    assert_eq!(branch_parses, 1);

    checkout(&repo, &main_ref);
    let (_, revisit_parses) = build_with_parse_count(project);
    assert_eq!(revisit_parses, 0);
}

#[test]
fn non_git_workspace_uses_in_memory_store_for_queries() {
    let built = InlineTestProject::with_language(Language::Python)
        .file("pkg/example.py", "class Example:\n    pass\n")
        .build();

    let analyzer = built.workspace_analyzer(AnalyzerConfig::default());
    let declarations = analyzer.analyzer().get_definitions("pkg.example.Example");

    assert_eq!(declarations.len(), 1);
    assert!(!built.root().join(".brokk/bifrost_cache.db").exists());
}

#[test]
fn persisted_build_triggers_analyzer_store_gc() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repo = init_repo(&root);
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    let reachable_source = "class Reachable:\n    pass\n";
    let dirty_source = "class Dirty:\n    pass\n";
    std::fs::write(root.join("pkg/reachable.py"), reachable_source).unwrap();
    commit_all(&repo, "reachable");
    std::fs::write(root.join("pkg/dirty.py"), dirty_source).unwrap();

    let reachable_oid = Oid::hash_object(ObjectType::Blob, reachable_source.as_bytes()).unwrap();
    let dirty_oid = Oid::hash_object(ObjectType::Blob, dirty_source.as_bytes()).unwrap();
    let bogus_oid = Oid::hash_object(ObjectType::Blob, b"not reachable anywhere").unwrap();

    let store = AnalyzerStore::open_for_workspace(&root).unwrap();
    store.gc_with(|_| true).unwrap();

    let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Python));
    let _ = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    assert!(store.contains_blob(reachable_oid, "python").unwrap());
    assert!(store.contains_blob(dirty_oid, "python").unwrap());

    store.register_blobs(&[bogus_oid], "python").unwrap();
    assert!(store.contains_blob(bogus_oid, "python").unwrap());

    let _guard = brokk_bifrost::analyzer::store::gc::set_min_interval_secs_for_test(0);
    let _ = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default());

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && store.contains_blob(bogus_oid, "python").unwrap() {
        std::thread::sleep(Duration::from_millis(25));
    }

    assert!(
        !store.contains_blob(bogus_oid, "python").unwrap(),
        "wired GC should remove the unreachable injected blob row"
    );
    assert!(
        store.contains_blob(reachable_oid, "python").unwrap(),
        "committed reachable blob should survive GC"
    );
    assert!(
        store.contains_blob(dirty_oid, "python").unwrap(),
        "uncommitted worktree blob should survive GC"
    );
}

#[test]
fn linked_worktrees_share_rows_and_second_build_parses_zero_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let repo = init_repo(&root);
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(root.join("pkg/alpha.py"), "class Alpha:\n    pass\n").unwrap();
    std::fs::write(root.join("pkg/beta.py"), "class Beta:\n    pass\n").unwrap();
    commit_all(&repo, "init");

    let linked_root = temp.path().join("linked");
    let worktree = repo.worktree("linked", &linked_root, None).unwrap();
    let _linked_repo = Repository::open_from_worktree(&worktree).unwrap();
    let linked_root = linked_root.canonicalize().unwrap();

    assert_eq!(analyzer_db_path(&root), analyzer_db_path(&linked_root));

    let primary_project: Arc<dyn Project> =
        Arc::new(TestProject::new(root.clone(), Language::Python));
    let (_, primary_parses) = build_with_parse_count(primary_project);
    assert_eq!(primary_parses, 2);

    let linked_project: Arc<dyn Project> =
        Arc::new(TestProject::new(linked_root, Language::Python));
    let (linked, linked_parses) = build_with_parse_count(linked_project);
    assert_eq!(linked_parses, 0);
    assert_eq!(
        linked.analyzer().get_definitions("pkg.alpha.Alpha").len(),
        1
    );
    assert_eq!(linked.analyzer().get_definitions("pkg.beta.Beta").len(), 1);
}
