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
        dead_code_file_paths: Vec::new(),
        dead_code_fq_names: Vec::new(),
        dead_code_expect_report_contains: Vec::new(),
        dead_code_expect_report_absent: Vec::new(),
        definition_queries: Vec::new(),
        call_hierarchy_queries: Vec::new(),
        type_hierarchy_queries: Vec::new(),
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
