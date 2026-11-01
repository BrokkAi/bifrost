use super::*;
use brokk_bifrost_core::gitblob::test_repo;

#[test]
fn committed_source_snapshot_accepts_its_exact_byte_limit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    let repo = test_repo::init_repo(root);
    fs::create_dir(root.join("src")).unwrap();
    let source = "pub fn answer() -> i32 { 42 }\n";
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let commit = test_repo::commit_all(&repo, "source");
    let image = RevisionImage::materialize_file_dependencies(
        &repo,
        Snapshot::Commit(commit),
        &BTreeSet::from([Language::Rust]),
        &[],
    )
    .expect("committed revision image");
    let (project, _) = image.project();
    let file = project
        .file_by_rel_path(Path::new("src/lib.rs"))
        .expect("source file");

    assert!(
        project
            .read_source_snapshot_limited(&file, source.len() - 1)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        project
            .read_source_snapshot_limited(&file, source.len())
            .unwrap()
            .expect("exact-size committed source")
            .source(),
        source
    );
}

#[test]
fn committed_revision_ignore_rules_have_distinct_digests() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    let repo = test_repo::init_repo(root);
    fs::write(root.join(".bifrostignore"), "").unwrap();
    fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();
    let first = test_repo::commit_all(&repo, "before ignore");
    fs::write(root.join(".bifrostignore"), "main.rs\n").unwrap();
    let second = test_repo::commit_all(&repo, "after ignore");
    let before = RevisionImage::materialize(&repo, Snapshot::Commit(first), None, &[], None)
        .expect("before image");
    let after = RevisionImage::materialize(&repo, Snapshot::Commit(second), None, &[], None)
        .expect("after image");
    let (before, _) = before.project();
    let (after, _) = after.project();
    assert!(!before.is_bifrostignored(Path::new("main.rs")));
    assert!(after.is_bifrostignored(Path::new("main.rs")));
    assert_ne!(
        before.ignore_rules_digest().unwrap(),
        after.ignore_rules_digest().unwrap()
    );
}

#[test]
fn file_dependency_placeholder_reads_committed_snapshot_bytes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    let repo = test_repo::init_repo(root);
    fs::create_dir(root.join("src")).unwrap();
    let source = b"pub fn answer() -> i32 { 42 }\n";
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let commit = test_repo::commit_all(&repo, "source");
    let image = RevisionImage::materialize_file_dependencies(
        &repo,
        Snapshot::Commit(commit),
        &BTreeSet::from([Language::Rust]),
        &[],
    )
    .expect("file dependency image");
    let (project, _) = image.project();
    let file = project
        .file_by_rel_path(Path::new("src/lib.rs"))
        .expect("source file");

    assert_eq!(
        fs::read(image.root().join("src/lib.rs")).unwrap(),
        b"",
        "export keeps only a placeholder"
    );
    assert_eq!(project.read_file_snapshot(&file).unwrap().bytes(), source);
}
