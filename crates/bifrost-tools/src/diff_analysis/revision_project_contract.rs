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
        ImageCheckout::of_root(&repo),
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
    let before = RevisionImage::materialize(
        &repo,
        ImageCheckout::of_root(&repo),
        Snapshot::Commit(first),
        None,
        &[],
        None,
        None,
    )
    .expect("before image");
    let after = RevisionImage::materialize(
        &repo,
        ImageCheckout::of_root(&repo),
        Snapshot::Commit(second),
        None,
        &[],
        None,
        None,
    )
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
        ImageCheckout::of_root(&repo),
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

/// A tree walk that skips a symbolic link entry would let a `mod` directory or a
/// `#[path]` target that is a link count as proven absent. The image records
/// the entry as an omission instead, which fails the Rust listing certificate,
/// so every route answer about the revision is incomplete. The exact-file
/// control shows that the same layout with a real `src/feature.rs` stays
/// certified.
#[cfg(unix)]
#[test]
fn a_revision_symlink_entry_fails_the_rust_listing_certificate() {
    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
    use brokk_bifrost_rust::graph_support::RustSource;
    use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

    let mut outcomes = Vec::new();
    for (with_link, with_file) in [(false, false), (true, false), (false, true)] {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let repo = test_repo::init_repo(root);
        fs::create_dir(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"linked\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "mod feature;\n").unwrap();
        fs::create_dir(root.join("elsewhere")).unwrap();
        fs::write(root.join("elsewhere/mod.rs"), "pub fn f() {}\n").unwrap();
        if with_link {
            std::os::unix::fs::symlink("../elsewhere", root.join("src/feature")).unwrap();
        }
        if with_file {
            fs::write(root.join("src/feature.rs"), "pub fn f() {}\n").unwrap();
        }
        let commit = test_repo::commit_all(&repo, "revision");
        let languages = BTreeSet::from([Language::Rust]);
        let image = RevisionImage::materialize_file_dependencies(
            &repo,
            ImageCheckout::of_root(&repo),
            Snapshot::Commit(commit),
            &languages,
            &[],
        )
        .expect("file dependency image");
        let (project, _) = image.project();
        let (_, omissions) = project.all_files_with_omissions().unwrap();
        let omitted = omissions
            .iter()
            .map(|omission| (omission.path.clone(), omission.reason))
            .collect::<Vec<_>>();

        let analyzer = build_file_dependency_analyzer(
            &image,
            None,
            &languages,
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        )
        .expect("revision analyzer");
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer.analyzer())
            .expect("revision analyzer holds the Rust analyzer");
        let lib = ProjectFile::new(image.root().to_path_buf(), "src/lib.rs");
        let complete = RustSource::file_routes(rust, &lib, None)
            .expect("file routes")
            .is_complete();
        outcomes.push((omitted, complete));
    }
    let placed = outcomes.pop().unwrap();
    assert_eq!(placed, (Vec::new(), true), "placed module: complete");
    let linked = outcomes.pop().unwrap();
    let plain = outcomes.pop().unwrap();
    assert_eq!(plain, (Vec::new(), true), "no link: certified absence");
    assert_eq!(
        linked,
        (
            vec![(
                PathBuf::from("src/feature"),
                brokk_bifrost_core::analyzer::project::WorkspaceFileOmissionReason::UnreadableSymlink
            )],
            false
        ),
        "a symlink entry: recorded, and the route answer is incomplete"
    );
}
