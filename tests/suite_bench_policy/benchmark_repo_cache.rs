use brokk_bifrost::benchmark::repo_cache::prepare_repo;
use brokk_bifrost::benchmark::{BenchmarkRepoTarget, BenchmarkScenario, ManifestLanguage};
use git2::Repository;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn prepare_repo_reuses_cached_commit_without_fetching_origin() {
    let temp = TempDir::new().expect("temp dir");
    let source_root = temp.path().join("source");
    fs::create_dir_all(&source_root).expect("source root");
    init_git_repo(&source_root);

    let cache_root = temp.path().join("cache");
    let target = repo_target(&source_root, &head_commit(&source_root));
    let checkout = prepare_repo(&target, &cache_root).expect("initial clone");
    set_origin_url(&checkout, "https://invalid.example/offline.git");

    let reused = prepare_repo(&target, &cache_root).expect("reuse cached commit");
    assert_eq!(checkout, reused);
}

#[test]
fn prepare_repo_disables_autocrlf_for_deterministic_checkout_bytes() {
    let temp = TempDir::new().expect("temp dir");
    let source_root = temp.path().join("source");
    fs::create_dir_all(&source_root).expect("source root");
    init_git_repo(&source_root);

    let cache_root = temp.path().join("cache");
    let target = repo_target(&source_root, &head_commit(&source_root));
    let checkout = prepare_repo(&target, &cache_root).expect("initial clone");
    let repo = Repository::open(checkout).expect("open checkout");

    assert_eq!(
        repo.config()
            .expect("checkout config")
            .get_string("core.autocrlf")
            .expect("autocrlf config"),
        "false"
    );
    let checkout_bytes = fs::read(repo.workdir().expect("checkout workdir").join("lib.rs"))
        .expect("read checked-out fixture");
    assert_eq!(checkout_bytes, b"pub fn fixture() {}\n");

    let head = repo
        .head()
        .expect("checkout head")
        .peel_to_commit()
        .unwrap();
    let committed_oid = head
        .tree()
        .unwrap()
        .get_path(Path::new("lib.rs"))
        .unwrap()
        .id();
    let working_oid = git2::Oid::hash_object(git2::ObjectType::Blob, &checkout_bytes).unwrap();
    assert_eq!(working_oid, committed_oid);
}

/// A cached blobless clone left by the pre-#1373 harness (or a restored CI
/// cache) must be upgraded to a full clone: `most_relevant_files` refuses the
/// git history walk on a partial clone with a network promisor remote, so a
/// blobless fixture benchmarks the import-only fallback instead of the pinned
/// history ranking. The upgrade runs in place through `git fetch --refetch` on
/// git 2.36 or later, and through a discard-and-re-clone on older git (issue
/// #1727); the assertions below describe the end state that both paths reach.
#[test]
fn prepare_repo_upgrades_a_cached_blobless_clone_to_a_full_clone() {
    let temp = TempDir::new().expect("temp dir");
    let source_root = temp.path().join("source");
    fs::create_dir_all(&source_root).expect("source root");
    init_git_repo(&source_root);

    let cache_root = temp.path().join("cache");
    fs::create_dir_all(&cache_root).expect("cache root");
    let checkout_path = cache_root.join("fixture-repo");
    // file:// forces the partial-clone transport; a plain local path would
    // silently ignore the filter.
    let source_url = format!("file://{}", source_root.display());
    let clone = std::process::Command::new("git")
        .arg("clone")
        .arg("--no-checkout")
        .arg("--filter=blob:none")
        .arg(&source_url)
        .arg(&checkout_path)
        .output()
        .expect("run git clone");
    assert!(clone.status.success(), "{clone:?}");
    {
        let repo = Repository::open(&checkout_path).expect("open blobless clone");
        let config = repo.config().expect("clone config");
        assert!(
            config.get_bool("remote.origin.promisor").unwrap_or(false),
            "the fixture must start as a promisor partial clone"
        );
    }

    let target = repo_target(&source_root, &head_commit(&source_root));
    let prepared = prepare_repo(&target, &cache_root).expect("upgrade cached clone");

    let repo = Repository::open(&prepared).expect("open upgraded clone");
    let config = repo.config().expect("upgraded config");
    assert!(
        config.get_bool("remote.origin.promisor").is_err(),
        "promisor marker must be removed"
    );
    assert!(
        config
            .get_string("remote.origin.partialclonefilter")
            .is_err(),
        "partial-clone filter must be removed"
    );
    let missing = std::process::Command::new("git")
        .arg("-C")
        .arg(&prepared)
        .args(["rev-list", "--objects", "--all", "--missing=print"])
        .output()
        .expect("run git rev-list");
    assert!(missing.status.success(), "{missing:?}");
    let missing_objects: Vec<&str> = std::str::from_utf8(&missing.stdout)
        .expect("utf8 rev-list output")
        .lines()
        .filter(|line| line.starts_with('?'))
        .collect();
    assert_eq!(
        missing_objects,
        Vec::<&str>::new(),
        "every historical object must be present after the upgrade"
    );
}

fn repo_target(source_root: &Path, commit: &str) -> BenchmarkRepoTarget {
    BenchmarkRepoTarget {
        name: "fixture-repo".to_string(),
        url: source_root.display().to_string(),
        commit: commit.to_string(),
        languages: vec![ManifestLanguage::Rust],
        extensions: vec!["rs".to_string()],
        scenarios: vec![BenchmarkScenario::WorkspaceBuild],
        search_patterns: Vec::new(),
        location_symbols: Vec::new(),
        ancestor_symbols: Vec::new(),
        summary_targets: Vec::new(),
        seed_file_paths: Vec::new(),
        usage_symbols: Vec::new(),
        usage_targets: Vec::new(),
        code_quality_probes: Vec::new(),
        definition_queries: Vec::new(),
        call_hierarchy_queries: Vec::new(),
        type_hierarchy_queries: Vec::new(),
        query_code_queries: Vec::new(),
        interactive_queries: Vec::new(),
        mcp_fairness: None,
    }
}

fn init_git_repo(root: &Path) {
    fs::write(root.join("lib.rs"), "pub fn fixture() {}\n").expect("write fixture");
    let repo = Repository::init(root).expect("init git repo");
    let mut index = repo.index().expect("repo index");
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .expect("add all");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = git2::Signature::now("Test User", "test@example.com").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");
}

fn head_commit(root: &Path) -> String {
    let repo = Repository::open(root).expect("open repo");
    repo.head()
        .expect("head")
        .target()
        .expect("target")
        .to_string()
}

fn set_origin_url(root: &Path, url: &str) {
    let repo = Repository::open(root).expect("open repo");
    if repo.find_remote("origin").is_ok() {
        repo.remote_set_url("origin", url).expect("update origin");
    }
}
