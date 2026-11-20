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
    assert!(!before.is_bifrostignored(Path::new("main.rs")).unwrap());
    assert!(after.is_bifrostignored(Path::new("main.rs")).unwrap());
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
                brokk_bifrost_core::analyzer::project::WorkspaceFileOmissionReason::SymlinkToDirectory
            )],
            false
        ),
        "a symlink entry: recorded, and the route answer is incomplete"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9559: immutable revision images had no view stamp and could not certify JDK selections"
)]
fn revision_view_stamp_tracks_tree_and_visible_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let repo = test_repo::init_repo(temp.path());
    fs::write(temp.path().join("A.java"), "class A {}\n").unwrap();
    fs::write(temp.path().join("B.java"), "class B {}\n").unwrap();
    let first = test_repo::commit_all(&repo, "first tree");
    fs::write(temp.path().join("B.java"), "class B { int value; }\n").unwrap();
    let second = test_repo::commit_all(&repo, "second tree");
    let image = |oid| {
        RevisionImage::materialize(
            &repo,
            ImageCheckout::of_root(&repo),
            Snapshot::Commit(oid),
            None,
            &[],
            None,
            None,
        )
        .unwrap()
    };
    let first_image = image(first);
    let same_image = image(first);
    let second_image = image(second);
    let subset = RevisionImage::materialize_symbols(
        &repo,
        Snapshot::Commit(first),
        &["A.java".to_owned()],
        &[],
    )
    .unwrap();
    let stamp = |image: &RevisionImage| {
        image
            .project()
            .0
            .view_stamp()
            .expect("immutable image stamp")
    };
    assert_eq!(stamp(&first_image), stamp(&same_image));
    assert_ne!(stamp(&first_image), stamp(&second_image));
    assert_ne!(stamp(&first_image), stamp(&subset));
}

#[test]
fn revision_view_stamp_tracks_omissions_alone() {
    use brokk_bifrost_core::analyzer::project::{ImmutableTreeIdentity, ProjectViewStamp};
    let temp = tempfile::tempdir().unwrap();
    let repo = test_repo::init_repo(temp.path());
    fs::write(temp.path().join("A.java"), "class A {}\n").unwrap();
    let commit = test_repo::commit_all(&repo, "tree");
    let tree = snapshot_tree(&repo, Snapshot::Commit(commit)).unwrap();
    let visible = BTreeSet::from([PathBuf::from("A.java")]);
    let omissions = vec![WorkspaceFileOmission {
        path: PathBuf::from("submodule"),
        reason: WorkspaceFileOmissionReason::Unknown,
        bounded: None,
    }];
    let stamp = |omissions: &[WorkspaceFileOmission]| {
        ProjectViewStamp::immutable_content(&ImmutableTreeIdentity::from_tree(
            &tree, &visible, omissions,
        ))
    };
    assert_ne!(stamp(&[]), stamp(&omissions));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "75135e29d1fe: revision identity hashed lossy, slash-normalized paths, aliasing distinct names"
)]
fn revision_view_identity_keeps_distinct_path_names_distinct() {
    use brokk_bifrost_core::analyzer::project::{ImmutableTreeIdentity, ProjectViewStamp};
    let temp = tempfile::tempdir().unwrap();
    let repo = test_repo::init_repo(temp.path());
    fs::write(temp.path().join("A.java"), "class A {}\n").unwrap();
    let commit = test_repo::commit_all(&repo, "tree");
    let tree = snapshot_tree(&repo, Snapshot::Commit(commit)).unwrap();
    let stamp = |visible: &BTreeSet<PathBuf>| {
        ProjectViewStamp::immutable_content(&ImmutableTreeIdentity::from_tree(&tree, visible, &[]))
    };
    let nested = BTreeSet::from([PathBuf::from("a").join("b")]);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        // On Unix a backslash is an ordinary name byte, so `a\b` is one
        // component and must not alias the nested path `a/b`.
        let backslash = BTreeSet::from([PathBuf::from("a\\b")]);
        assert_ne!(stamp(&nested), stamp(&backslash));
        // Two names that differ only in invalid UTF-8 must stay distinct.
        let first = BTreeSet::from([PathBuf::from(std::ffi::OsStr::from_bytes(b"x\xff"))]);
        let second = BTreeSet::from([PathBuf::from(std::ffi::OsStr::from_bytes(b"x\xfe"))]);
        assert_ne!(stamp(&first), stamp(&second));
    }
    assert_eq!(stamp(&nested), stamp(&nested.clone()));
}

#[test]
fn revision_worktree_image_tracks_live_delegate() {
    let temp = tempfile::tempdir().unwrap();
    let repo = test_repo::init_repo(temp.path());
    fs::write(temp.path().join("A.java"), "class A {}\n").unwrap();
    let image = RevisionImage::materialize(
        &repo,
        ImageCheckout::of_root(&repo),
        Snapshot::Worktree,
        None,
        &[],
        None,
        None,
    )
    .unwrap();
    let project = image.project().0;
    let before = project.view_stamp().unwrap();
    fs::create_dir_all(temp.path().join(".bifrost")).unwrap();
    let config = temp.path().join(".bifrost/jvm-toolchains.json");
    fs::write(&config, "{}").unwrap();
    let file = brokk_bifrost_core::analyzer::ProjectFile::new(
        temp.path().to_path_buf(),
        PathBuf::from(".bifrost/jvm-toolchains.json"),
    );
    fs::write(&config, "{ \"schema_version\": 1 }").unwrap();
    assert_eq!(
        project.read_source_snapshot(&file).unwrap().source(),
        "{ \"schema_version\": 1 }"
    );

    fs::write(temp.path().join("A.java"), "class A { int changed; }\n").unwrap();
    project.invalidate_cached_file_listing();
    assert_ne!(Some(before), project.view_stamp());
    let subset = FileSetProject::new(temp.path(), [PathBuf::from("A.java")]);
    assert_eq!(subset.view_stamp(), None);
    let RevisionImage::Worktree {
        live_delegate,
        live_inventory,
        ..
    } = &image
    else {
        unreachable!()
    };
    let other = FileSetProject::new(live_delegate.root(), [])
        .with_live_delegate(Arc::clone(live_delegate), Arc::clone(live_inventory));
    assert_ne!(project.view_stamp(), other.view_stamp());
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#13574: a worktree image rooted at the raw tempdir path did not match its canonical live delegate"
)]
fn revision_worktree_image_root_matches_its_live_delegate() {
    let temp = tempfile::tempdir().unwrap();
    let repo = test_repo::init_repo(temp.path());
    fs::write(temp.path().join("A.java"), "class A {}\n").unwrap();
    let whole = RevisionImage::materialize(
        &repo,
        ImageCheckout::of_root(&repo),
        Snapshot::Worktree,
        None,
        &[],
        None,
        None,
    )
    .unwrap();
    let file_dependencies = RevisionImage::materialize_file_dependencies(
        &repo,
        ImageCheckout::of_root(&repo),
        Snapshot::Worktree,
        &BTreeSet::from([Language::Java]),
        &[],
    )
    .unwrap();
    for image in [whole, file_dependencies] {
        let RevisionImage::Worktree { live_delegate, .. } = &image else {
            unreachable!()
        };
        assert_eq!(image.root(), live_delegate.root());
        assert!(image.project().0.view_stamp().is_some());
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9559: symbol-only worktree materialization walked unrelated files and lacked a typed resolution refusal"
)]
fn symbol_only_worktree_image_lists_only_selected_paths_and_has_no_stamp() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let repo = test_repo::init_repo(root);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/Main.java"), "class Main {}\n").unwrap();
    fs::create_dir_all(root.join("outside")).unwrap();
    fs::write(root.join("outside/Other.java"), "class Other {}\n").unwrap();
    // A whole-root FilesystemProject would discover this file, then fail while
    // compiling the ignore rules from the unrelated subtree.
    fs::write(root.join("outside/.bifrostignore"), "[\n").unwrap();

    let image = RevisionImage::materialize_symbols(
        &repo,
        Snapshot::Worktree,
        &["src/Main.java".to_owned()],
        &[],
    )
    .expect("symbol-only materialization must not inspect unrelated subtrees");
    let (project, _) = image.project();

    assert_eq!(image.files(), &[PathBuf::from("src/Main.java")]);
    assert_eq!(project.view_stamp(), None);
    assert!(matches!(image, RevisionImage::SymbolOnlyWorktree { .. }));
    let resolution = build_file_dependency_analyzer(
        &image,
        None,
        &BTreeSet::from([Language::Java]),
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    );
    assert!(matches!(
        resolution,
        Err(RevisionImageBuildError::SymbolOnlyWorktreeCannotResolve)
    ));
    let calls = build_revision_analyzer(
        &image,
        None,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    );
    assert!(matches!(
        calls,
        Err(RevisionImageBuildError::SymbolOnlyWorktreeCannotResolve)
    ));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9559: worktree revision projects cannot certify their pinned JDK selection"
)]
fn revision_worktree_jdk_selection_is_certified_warm_and_cold() {
    use brokk_bifrost_core::analyzer::external_selection::{
        ExternalSelectionAuthority, ExternalSelectionQuestion, SelectionRetry,
    };
    use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
    use brokk_bifrost_jvm_analysis::analyzer::jvm::catalog_reader::JvmSelectionAuthority;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let repo = test_repo::init_repo(&workspace);
    fs::write(workspace.join("A.java"), "class A {}\n").unwrap();
    let home = root.join("jdk");
    fs::create_dir_all(home.join("jmods")).unwrap();
    fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
    fs::write(home.join("jmods/java.base.jmod"), b"jmod bytes").unwrap();
    let image = RevisionImage::materialize(
        &repo,
        ImageCheckout::of_root(&repo),
        Snapshot::Worktree,
        None,
        &[],
        None,
        None,
    )
    .unwrap();
    let mut config = brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig::default();
    config.standard_library_discovery.discover_java_home = false;
    config.standard_library_discovery.jdk_homes = vec![home];
    let question = ExternalSelectionQuestion::for_jvm(&config).remove(1);
    let authority = JvmSelectionAuthority {
        config,
        project: image.project().0,
        verifications: Arc::default(),
        digests: brokk_bifrost_core::content_digest::ContentDigestCache::new(
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        ),
    };
    let select = || {
        authority
            .answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &Default::default(),
            )
            .unwrap()
    };
    let cold = select();
    let warm = select();
    assert_eq!(cold.answer_digest, warm.answer_digest);
    assert!(cold.complete && warm.complete);
    assert!(
        cold.certified && warm.certified,
        "cold={cold:?}, warm={warm:?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9559: consecutive worktree requests must certify newly read configuration"
)]
fn revision_worktree_requests_have_fresh_certifications() {
    use brokk_bifrost_core::analyzer::external_selection::{
        ExternalSelectionAuthority, ExternalSelectionQuestion, SelectionRetry,
    };
    use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
    use brokk_bifrost_jvm_analysis::analyzer::jvm::catalog_reader::JvmSelectionAuthority;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repo = test_repo::init_repo(&root);
    fs::write(root.join("A.java"), "class A {}\n").unwrap();
    let home = root.join("jdk");
    fs::create_dir_all(home.join("jmods")).unwrap();
    fs::write(home.join("release"), "JAVA_VERSION=\"21.0.8\"\n").unwrap();
    fs::write(home.join("jmods/java.base.jmod"), b"jmod bytes").unwrap();
    // Unix ctime cannot be backdated. A verified JDK selection is reused only
    // outside the racy timestamp window, so wait it out to record a stable
    // observation rather than re-verifying the fresh fixture on every request.
    std::thread::sleep(
        brokk_bifrost_core::content_digest::FILE_TIMESTAMP_GRANULARITY
            + std::time::Duration::from_millis(100),
    );
    let mut config = brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig::default();
    config.standard_library_discovery.discover_java_home = false;
    config.standard_library_discovery.jdk_homes = vec![home];
    let questions = ExternalSelectionQuestion::for_jvm(&config);
    let verifications = Arc::default();
    let mut previous = None;
    for manifest in ["<project/>", "<project><name>edited</name></project>"] {
        fs::write(root.join("pom.xml"), manifest).unwrap();
        let image = RevisionImage::materialize(
            &repo,
            ImageCheckout::of_root(&repo),
            Snapshot::Worktree,
            None,
            &[],
            None,
            None,
        )
        .unwrap();
        let authority = JvmSelectionAuthority {
            config: config.clone(),
            project: image.project().0,
            verifications: Arc::clone(&verifications),
            digests: brokk_bifrost_core::content_digest::ContentDigestCache::new(
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            ),
        };
        let request = OuterRequest::new();
        let answers: Vec<_> = questions
            .iter()
            .map(|question| {
                authority
                    .answer(
                        &request,
                        question,
                        &SelectionRetry::default(),
                        &Default::default(),
                    )
                    .unwrap()
            })
            .collect();
        assert!(
            answers
                .iter()
                .all(|answer| answer.complete && answer.certified),
            "{answers:?}"
        );
        assert_eq!(
            authority
                .project
                .read_source(&brokk_bifrost_core::analyzer::ProjectFile::new(
                    &root, "pom.xml"
                ))
                .unwrap(),
            manifest
        );
        if let Some((stamp, digest, records)) = previous {
            assert_ne!(stamp, authority.project.view_stamp());
            // The manifest edit changes no selected dependency artifacts.
            assert_eq!(digest, answers[0].answer_digest);
            // The exact selected JDK allocation survives the fresh view and a
            // fresh digest cache: zero JDK content verification calls on reuse.
            assert!(Arc::ptr_eq(&records, &answers[1].records));
        }
        previous = Some((
            authority.project.view_stamp(),
            answers[0].answer_digest,
            Arc::clone(&answers[1].records),
        ));
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9559: restricted worktree inventory certified a newly added or removed manifest"
)]
fn revision_worktree_dependency_selection_refuses_inventory_drift() {
    use brokk_bifrost_core::analyzer::external_selection::{
        ExternalSelectionAuthority, ExternalSelectionQuestion, SelectionRetry,
    };
    use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
    use brokk_bifrost_jvm_analysis::analyzer::jvm::catalog_reader::JvmSelectionAuthority;

    let temp = tempfile::tempdir().unwrap();
    let repo = test_repo::init_repo(temp.path());
    fs::write(temp.path().join("A.java"), "class A {}").unwrap();
    for removal in [false, true] {
        let manifest = temp.path().join("pom.xml");
        if removal {
            fs::write(&manifest, "<project/>").unwrap();
        }
        let image = RevisionImage::materialize(
            &repo,
            ImageCheckout::of_root(&repo),
            Snapshot::Worktree,
            None,
            &[],
            None,
            None,
        )
        .unwrap();
        let config = brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig::default();
        let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
        let authority = JvmSelectionAuthority {
            config,
            project: image.project().0,
            verifications: Arc::default(),
            digests: brokk_bifrost_core::content_digest::ContentDigestCache::new(
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            ),
        };
        let initial = authority
            .answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &Default::default(),
            )
            .unwrap();
        assert!(initial.complete && initial.certified, "{initial:?}");
        if removal {
            fs::remove_file(&manifest).unwrap();
        } else {
            fs::write(&manifest, "<project/>").unwrap();
        }
        let answer = authority.answer(
            &OuterRequest::new(),
            &question,
            &SelectionRetry::default(),
            &Default::default(),
        );
        assert!(
            answer.is_err(),
            "inventory drift must refuse certification: {answer:?}"
        );
        if !removal {
            fs::remove_file(&manifest).unwrap();
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9559: stamped restricted revisions certified absent manifests outside their visible inventory"
)]
fn revision_dependency_selection_requires_complete_inventory() {
    use brokk_bifrost_core::analyzer::external_selection::{
        ExternalSelectionAuthority, ExternalSelectionQuestion, SelectionRetry,
    };
    use brokk_bifrost_core::analyzer::outer_request::OuterRequest;
    use brokk_bifrost_jvm_analysis::analyzer::jvm::catalog_reader::JvmSelectionAuthority;

    let temp = tempfile::tempdir().unwrap();
    let repo = test_repo::init_repo(temp.path());
    fs::write(temp.path().join("A.java"), "class A {}").unwrap();
    fs::create_dir(temp.path().join("module")).unwrap();
    fs::write(temp.path().join("module/pom.xml"), "<project/>").unwrap();
    let commit = test_repo::commit_all(&repo, "manifest outside selected paths");
    for snapshot in [Snapshot::Commit(commit)] {
        let whole = RevisionImage::materialize(
            &repo,
            ImageCheckout::of_root(&repo),
            snapshot,
            None,
            &[],
            None,
            None,
        )
        .unwrap();
        let subset =
            RevisionImage::materialize_symbols(&repo, snapshot, &["A.java".to_owned()], &[])
                .unwrap();
        for (image, complete) in [(&whole, true), (&subset, false)] {
            let config = brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig::default();
            let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
            let authority = JvmSelectionAuthority {
                config,
                project: image.project().0,
                verifications: Arc::default(),
                digests: brokk_bifrost_core::content_digest::ContentDigestCache::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            };
            assert!(authority.project.view_stamp().is_some());
            let answer = authority
                .answer(
                    &OuterRequest::new(),
                    &question,
                    &SelectionRetry::default(),
                    &Default::default(),
                )
                .unwrap();
            assert_eq!(answer.complete, complete, "{snapshot:?}: {answer:?}");
            assert_eq!(answer.certified, complete, "{snapshot:?}: {answer:?}");
        }
    }

    // The image omits every committed symlink; the omission blocks
    // certification only where the link could hide a manifest (#13399).
    // `linked-pom.xml` resolves to a file at a path Maven never reads, as the
    // worktree listing also finds, so the selection stays certified. A link at
    // a manifest path, `linked/pom.xml`, is an omitted manifest.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("module/pom.xml", temp.path().join("linked-pom.xml")).unwrap();
        let irrelevant = test_repo::commit_all(&repo, "symlink at a non-manifest path");
        fs::create_dir(temp.path().join("linked")).unwrap();
        std::os::unix::fs::symlink("../module/pom.xml", temp.path().join("linked/pom.xml"))
            .unwrap();
        let relevant = test_repo::commit_all(&repo, "symlink at a manifest path");
        for (commit, complete) in [(irrelevant, true), (relevant, false)] {
            let image = RevisionImage::materialize(
                &repo,
                ImageCheckout::of_root(&repo),
                Snapshot::Commit(commit),
                None,
                &[],
                None,
                None,
            )
            .unwrap();
            let config = brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig::default();
            let question = ExternalSelectionQuestion::for_jvm(&config).remove(0);
            let authority = JvmSelectionAuthority {
                config,
                project: image.project().0,
                verifications: Arc::default(),
                digests: brokk_bifrost_core::content_digest::ContentDigestCache::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            };
            let answer = authority
                .answer(
                    &OuterRequest::new(),
                    &question,
                    &SelectionRetry::default(),
                    &Default::default(),
                )
                .unwrap();
            assert_eq!(answer.complete, complete, "{commit}: {answer:?}");
            assert_eq!(answer.certified, complete, "{commit}: {answer:?}");
        }
    }
}
