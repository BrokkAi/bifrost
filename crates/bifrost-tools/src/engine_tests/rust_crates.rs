#[cfg(test)]
pub(in crate::engine_tests) mod tests {
    use brokk_bifrost_core::analyzer::project::Project;
    use brokk_bifrost_core::analyzer::rust_facts::RustVisibility;
    use brokk_bifrost_rust::cargo_routes::RustCargoModuleDeclaration;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use brokk_bifrost_analysis::analyzer::store::rust_crates::CREATE_PENDING_CRATES_SQL;

    use rusqlite::Connection;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::CrateReconcileScope;

    use brokk_bifrost_core::cache_gc::DELETE_UNBOUND_TOPOLOGIES_SQL;

    use std::collections::HashSet;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::INSERT_PENDING_CRATE_SQL;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::Member;

    use git2::Oid;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::RUST_CRATE_DERIVATION_VERSION;

    use brokk_bifrost_analysis::analyzer::store::Result;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::SQL_BLOBS_8;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::SQL_RUST_CRATE_DEPENDENCIES_12;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::SQL_RUST_CRATE_PENDING_ANCESTORS;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::crate_key_from_row;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation_version;

    use rusqlite::params;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::prepare_pin_context;

    use brokk_bifrost_analysis::analyzer::store::rust_crates::set_derivation_version;

    use brokk_bifrost_analysis::analyzer::store::unit_schedule;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_core::analyzer::{ProjectFile, model::Language};
    use brokk_bifrost_rust::graph_support::RustSource;

    fn write(root: &std::path::Path, path: &str, body: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn with_certified_rust_routes(
        root: &std::path::Path,
        check: impl FnOnce(&brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer),
    ) {
        let filesystem = crate::inline_project::certified_project_at(root);
        let analyzer =
            brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_persisted(
                filesystem,
                AnalyzerConfig::default(),
            )
            .unwrap();
        let brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::Multi(multi) =
            &analyzer
        else {
            panic!("Rust workspace missing")
        };
        let rust = multi.delegates().get(&Language::Rust).unwrap().analyzer();
        let rust = (rust as &dyn std::any::Any)
            .downcast_ref::<brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer>()
            .unwrap();
        check(rust);
    }

    struct IdentityView {
        delegate: brokk_bifrost_core::analyzer::project::TestProject,
        hidden: BTreeSet<PathBuf>,
        fail_listing: std::sync::atomic::AtomicBool,
        fail_identity: std::sync::atomic::AtomicBool,
        stale_listing: std::sync::atomic::AtomicBool,
    }

    impl Project for IdentityView {
        fn root(&self) -> &Path {
            self.delegate.root()
        }
        fn analyzer_languages(&self) -> BTreeSet<Language> {
            let files = self.delegate.all_files().unwrap();
            self.delegate
                .analyzer_languages()
                .into_iter()
                .filter(|language| files.iter().any(|file| file.language() == *language))
                .collect()
        }
        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            if self.fail_listing.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(std::io::Error::other("injected enumeration failure"));
            }
            Ok(self
                .delegate
                .all_files()?
                .into_iter()
                .filter(|file| {
                    !(self
                        .stale_listing
                        .load(std::sync::atomic::Ordering::Relaxed)
                        && matches!(
                            file.rel_path().to_str(),
                            Some("src/linked.rs" | "src/linked.js" | "src/Added.java")
                        ))
                        && !self
                            .hidden
                            .iter()
                            .any(|hidden| file.rel_path().starts_with(hidden))
                })
                .collect())
        }
        fn all_files_with_omissions(
            &self,
        ) -> std::io::Result<brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>
        {
            Ok((
                std::sync::Arc::new(self.all_files()?),
                std::sync::Arc::new(Vec::new()),
            ))
        }
        fn invalidate_cached_file_listing(&self) {
            self.stale_listing
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        fn directory_entries(&self, parent: &Path) -> std::io::Result<BTreeSet<ProjectFile>> {
            if self
                .fail_identity
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                // A vanished entry forces the real identity probe to fail.
                return Ok(BTreeSet::from([ProjectFile::new(self.root(), "vanished")]));
            }
            Ok(self
                .delegate
                .directory_entries(parent)?
                .into_iter()
                .filter(|file| {
                    !self
                        .hidden
                        .iter()
                        .any(|hidden| file.rel_path().starts_with(hidden))
                })
                .collect())
        }
        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.analyzable_files_from(&self.all_files()?, language)
        }
        fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(path)
        }
        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            self.delegate.read_source(file)
        }
        fn ignore_rules_digest(&self) -> std::io::Result<[u8; 32]> {
            self.delegate.ignore_rules_digest()
        }
    }

    #[test]
    #[hardwon("#11129: workspace enumeration failures panicked instead of failing the update")]
    fn update_listing_failure_publishes_failed_configured_update() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::TestProject;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"identity\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", "pub fn before() {}\n");
        let project = std::sync::Arc::new(IdentityView {
            delegate: TestProject::new(&root, Language::Rust),
            hidden: BTreeSet::new(),
            fail_listing: std::sync::atomic::AtomicBool::new(false),
            fail_identity: std::sync::atomic::AtomicBool::new(false),
            stale_listing: std::sync::atomic::AtomicBool::new(false),
        });
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        project
            .fail_listing
            .store(true, std::sync::atomic::Ordering::Relaxed);
        write(&root, "src/lib.rs", "pub fn after() {}\n");
        let updated = analyzer.update(&BTreeSet::from([ProjectFile::new(&root, "src/lib.rs")]));
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let _attribution = context.enter();
        updated.analyzer().begin_query(&context);
        assert!(
            context
                .store_error()
                .unwrap()
                .to_string()
                .contains("injected enumeration failure")
        );
        updated.analyzer().end_query(&context);
        drop(_attribution);
        project
            .fail_listing
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let recovered = updated.update(&BTreeSet::new());
        assert!(recovered.test_pending_update_paths().is_empty());
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let _attribution = context.enter();
        recovered.analyzer().begin_query(&context);
        assert!(context.store_error().is_none());
        recovered.analyzer().end_query(&context);
        let fresh =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        let files = [ProjectFile::new(&root, "src/lib.rs")];
        assert_eq!(
            recovered.analyzer().test_files_to_code_units(&files),
            fresh.analyzer().test_files_to_code_units(&files)
        );
    }

    #[test]
    #[hardwon("#11129: identity probe failures silently retained stale content")]
    fn update_identity_failure_publishes_failed_configured_update() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::TestProject;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"identity\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", "pub fn before() {}\n");
        let project = std::sync::Arc::new(IdentityView {
            delegate: TestProject::new(&root, Language::Rust),
            hidden: BTreeSet::from([PathBuf::from("src/alias.rs")]),
            fail_listing: std::sync::atomic::AtomicBool::new(false),
            fail_identity: std::sync::atomic::AtomicBool::new(false),
            stale_listing: std::sync::atomic::AtomicBool::new(false),
        });
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        project
            .fail_identity
            .store(true, std::sync::atomic::Ordering::Relaxed);
        write(&root, "src/lib.rs", "pub fn after() {}\n");
        std::fs::hard_link(root.join("src/lib.rs"), root.join("src/alias.rs")).unwrap();
        let updated = analyzer.update(&BTreeSet::from([ProjectFile::new(&root, "src/alias.rs")]));
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let _attribution = context.enter();
        updated.analyzer().begin_query(&context);
        assert!(context.store_error().is_some());
        updated.analyzer().end_query(&context);
        project
            .fail_identity
            .store(false, std::sync::atomic::Ordering::Relaxed);
        write(&root, "src/other.rs", "pub fn other() {}\n");
        let recovered = updated
            .clone()
            .update(&BTreeSet::from([ProjectFile::new(&root, "src/other.rs")]));
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let _attribution = context.enter();
        recovered.analyzer().begin_query(&context);
        let oid: String = recovered.store().unwrap().read_conn().unwrap().query_row(
            "SELECT blob_oid FROM workspace_file_versions WHERE rel_path = 'src/lib.rs' AND valid_until IS NULL ORDER BY valid_from DESC LIMIT 1", [], |row| row.get(0)).unwrap();
        let expected = git2::Oid::hash_object(git2::ObjectType::Blob, b"pub fn after() {}\n")
            .unwrap()
            .to_string();
        assert!(
            context.store_error().is_some() || oid == expected,
            "stale blob {oid}"
        );
        recovered.analyzer().end_query(&context);
    }

    #[test]
    #[hardwon("#11129: first source update in an empty workspace lost resolution errors")]
    fn update_empty_workspace_retains_failure() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::TestProject;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project = std::sync::Arc::new(IdentityView {
            delegate: TestProject::new(&root, Language::Rust),
            hidden: BTreeSet::from([PathBuf::from("src/alias.rs")]),
            fail_listing: std::sync::atomic::AtomicBool::new(false),
            fail_identity: std::sync::atomic::AtomicBool::new(false),
            stale_listing: std::sync::atomic::AtomicBool::new(false),
        });
        let empty =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        assert!(matches!(empty, WorkspaceAnalyzer::Empty(_)));
        write(&root, "src/lib.rs", "pub fn added() {}\n");
        std::fs::hard_link(root.join("src/lib.rs"), root.join("src/alias.rs")).unwrap();
        project
            .fail_identity
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = empty.update(&BTreeSet::from([ProjectFile::new(&root, "src/alias.rs")]));
        let failed = failed.clone().update(&BTreeSet::new());
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let _attribution = context.enter();
        failed.analyzer().begin_query(&context);
        assert!(context.store_error().is_some());
        failed.analyzer().end_query(&context);
    }

    #[test]
    #[hardwon("#11129: direct analyzer lost reported paths after a transient listing failure")]
    fn update_direct_analyzer_retries_failed_paths() {
        use brokk_bifrost_analysis::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
        use brokk_bifrost_core::analyzer::project::TestProject;
        use brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(&root, "src/original.js", "export function before() {}\n");
        let project = std::sync::Arc::new(IdentityView {
            delegate: TestProject::new(&root, Language::JavaScript),
            hidden: BTreeSet::new(),
            fail_listing: std::sync::atomic::AtomicBool::new(false),
            fail_identity: std::sync::atomic::AtomicBool::new(false),
            stale_listing: std::sync::atomic::AtomicBool::new(false),
        });
        let warm = TreeSitterAnalyzer::new(project.clone(), JavascriptAdapter);
        project
            .fail_listing
            .store(true, std::sync::atomic::Ordering::Relaxed);
        write(&root, "src/original.js", "export function after() {}\n");
        let file = ProjectFile::new(&root, "src/original.js");
        let failed = warm.update(&BTreeSet::from([file.clone()]));
        project
            .fail_listing
            .store(false, std::sync::atomic::Ordering::Relaxed);
        write(&root, "src/other.js", "export function other() {}\n");
        let recovered = failed
            .clone()
            .update(&BTreeSet::from([ProjectFile::new(&root, "src/other.js")]));
        assert!(recovered.test_pending_update_paths().is_empty());
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let _attribution = context.enter();
        recovered.begin_query(&context);
        assert!(context.store_error().is_none());
        recovered.end_query(&context);
        let fresh = TreeSitterAnalyzer::new(project, JavascriptAdapter);
        assert_eq!(
            recovered.test_files_to_code_units(std::slice::from_ref(&file)),
            fresh.test_files_to_code_units(&[file])
        );
    }

    #[test]
    #[hardwon("#11129: Multi update without a relevant delegate discarded listing failures")]
    fn update_multi_analyzer_retries_non_language_paths() {
        use brokk_bifrost_analysis::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::TestProject;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(&root, "src/original.js", "export function before() {}\n");
        let project = std::sync::Arc::new(IdentityView {
            delegate: TestProject::new(&root, Language::JavaScript),
            hidden: BTreeSet::new(),
            fail_listing: std::sync::atomic::AtomicBool::new(false),
            fail_identity: std::sync::atomic::AtomicBool::new(false),
            stale_listing: std::sync::atomic::AtomicBool::new(false),
        });
        let WorkspaceAnalyzer::Multi(warm) =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap()
        else {
            panic!("expected Multi analyzer")
        };
        project
            .fail_listing
            .store(true, std::sync::atomic::Ordering::Relaxed);
        write(&root, "README.md", "changed\n");
        let file = ProjectFile::new(&root, "README.md");
        let failed = warm.update(&BTreeSet::from([file.clone()]));
        assert_eq!(failed.test_pending_update_paths(), &BTreeSet::from([file]));
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let attribution = context.enter();
        failed.begin_query(&context);
        assert!(
            context
                .store_error()
                .unwrap()
                .to_string()
                .contains("injected enumeration failure")
        );
        failed.end_query(&context);
        drop(attribution);
        project
            .fail_listing
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let recovered = failed.clone().update(&BTreeSet::new());
        assert!(recovered.test_pending_update_paths().is_empty());
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let _attribution = context.enter();
        recovered.begin_query(&context);
        assert!(context.store_error().is_none());
        recovered.end_query(&context);
        let fresh =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        let file = ProjectFile::new(&root, "src/original.js");
        assert_eq!(
            recovered.test_files_to_code_units(std::slice::from_ref(&file)),
            fresh.analyzer().test_files_to_code_units(&[file])
        );
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#11129: direct non-Rust update dropped a newly listed symlink")]
    fn update_direct_analyzer_refreshes_symlink() {
        use brokk_bifrost_analysis::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        use brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(&root, "src/original.js", "export function original() {}\n");
        let repo = brokk_bifrost_core::gitblob::test_repo::init_repo(&root);
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repo, "initial");
        let cache = std::sync::Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project =
            std::sync::Arc::new(FilesystemProject::with_cached_listing(&root, cache).unwrap());
        let warm = TreeSitterAnalyzer::new(project.clone(), JavascriptAdapter);
        std::os::unix::fs::symlink(root.join("src/original.js"), root.join("src/linked.js"))
            .unwrap();
        let file = ProjectFile::new(&root, "src/linked.js");
        let warm = warm.update(&BTreeSet::from([file.clone()]));
        let warm_listing = warm.project.all_files_with_omissions().unwrap();
        let fresh_project = std::sync::Arc::new(FilesystemProject::new(&root).unwrap());
        let fresh_listing = fresh_project.all_files_with_omissions().unwrap();
        assert!(
            !fresh_listing.1.is_empty(),
            "fresh enumeration records symlink evidence"
        );
        assert_eq!(warm_listing.0, fresh_listing.0);
        assert_eq!(
            format!("{:?}", warm_listing.1),
            format!("{:?}", fresh_listing.1)
        );
        let fresh = TreeSitterAnalyzer::new(fresh_project, JavascriptAdapter);
        let warm_units = warm.test_files_to_code_units(std::slice::from_ref(&file));
        let fresh_units = fresh.test_files_to_code_units(&[file]);
        assert_eq!(warm_units, fresh_units);
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#11129: a symlink to a listed sibling was mistaken for a spelling alias")]
    fn update_workspace_refreshes_sibling_symlink_omissions() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(&root, "src/lib.rs", "pub fn original() {}\n");
        let repo = brokk_bifrost_core::gitblob::test_repo::init_repo(&root);
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repo, "initial");
        let cache = std::sync::Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project =
            std::sync::Arc::new(FilesystemProject::with_cached_listing(&root, cache).unwrap());
        let warm =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        std::os::unix::fs::symlink("lib.rs", root.join("src/linked.rs")).unwrap();
        let warm = warm.update(&BTreeSet::from([ProjectFile::new(&root, "src/linked.rs")]));
        let fresh_project = std::sync::Arc::new(FilesystemProject::new(&root).unwrap());
        let warm_listing = project.all_files_with_omissions().unwrap();
        let fresh_listing = fresh_project.all_files_with_omissions().unwrap();
        assert_eq!(warm_listing.0, fresh_listing.0);
        assert_eq!(
            format!("{:?}", warm_listing.1),
            format!("{:?}", fresh_listing.1)
        );
        let fresh =
            WorkspaceAnalyzer::build_ephemeral_footgun(fresh_project, AnalyzerConfig::default())
                .unwrap();
        assert_eq!(
            live_crate_rows(&warm.store().unwrap().read_conn().unwrap()),
            live_crate_rows(&fresh.store().unwrap().read_conn().unwrap())
        );
    }

    #[test]
    #[hardwon("#11129: a new language file was resolved without refreshing workspace membership")]
    fn update_new_language_file_refreshes_membership_before_routing() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write(&root, "src/lib.rs", "pub fn existing() {}\n");
        let repo = brokk_bifrost_core::gitblob::test_repo::init_repo(&root);
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repo, "initial");
        let cache = std::sync::Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = std::sync::Arc::new(
            FilesystemProject::with_cached_listing(&root, cache.clone()).unwrap(),
        );
        let warm =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        assert!(!warm.analyzer().languages().contains(&Language::Java));

        let walks = cache.walk_count();
        write(&root, "src/Added.java.tmp", "class Added {}\n");
        let temporary = ProjectFile::new(&root, "src/Added.java.tmp");
        let warm = warm.update(&BTreeSet::from([temporary.clone()]));
        std::fs::rename(temporary.abs_path(), root.join("src/Added.java")).unwrap();
        let java_file = ProjectFile::new(&root, "src/Added.java");
        let warm = warm.update(&BTreeSet::from([temporary, java_file.clone()]));
        assert_eq!(
            cache.walk_count(),
            walks,
            "atomic saves must point-patch membership"
        );
        let fresh_project =
            std::sync::Arc::new(FilesystemProject::with_cached_listing(&root, cache).unwrap());
        let fresh =
            WorkspaceAnalyzer::build_ephemeral_footgun(fresh_project, AnalyzerConfig::default())
                .unwrap();

        assert!(warm.analyzer().languages().contains(&Language::Java));
        let warm_units = warm
            .analyzer()
            .test_files_to_code_units(std::slice::from_ref(&java_file));
        let fresh_units = fresh.analyzer().test_files_to_code_units(&[java_file]);
        assert!(
            !fresh_units.is_empty(),
            "fresh Java delegate must receive the file"
        );
        assert_eq!(warm_units, fresh_units);
    }

    #[test]
    #[hardwon("#11129: a case-insensitive update alias became a second selected file")]
    fn update_alias_refreshes_only_authoritative_file_identities() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::TestProject;
        for (reported, hidden, second_link) in [
            ("src/foo.RS", false, false),
            ("src/Foo.rs", true, false),
            ("src/Foo.rs", false, false),
            ("src/Foo.rs", true, true),
            ("SRC/foo.RS", true, false),
            ("new/nested/file.rs", false, false),
            ("src/linked.rs", false, false),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            write(
                &root,
                "Cargo.toml",
                "[package]\nname = \"identity\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            );
            write(&root, "src/lib.rs", "pub fn lib() {}\n");
            write(&root, "src/foo.RS", "pub fn before() {}\n");
            if second_link {
                std::fs::hard_link(root.join("src/foo.RS"), root.join("src/other.rs")).unwrap();
            }
            let project = std::sync::Arc::new(IdentityView {
                delegate: TestProject::new(&root, Language::Rust),
                fail_listing: std::sync::atomic::AtomicBool::new(false),
                fail_identity: std::sync::atomic::AtomicBool::new(false),
                stale_listing: std::sync::atomic::AtomicBool::new(reported == "src/linked.rs"),
                hidden: if hidden {
                    BTreeSet::from([PathBuf::from(if reported.starts_with("SRC/") {
                        "SRC"
                    } else {
                        reported
                    })])
                } else {
                    BTreeSet::new()
                },
            });
            let warm = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.clone(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            if hidden && !root.join(reported).exists() {
                if reported.starts_with("SRC/") {
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(root.join("src"), root.join("SRC")).unwrap();
                    #[cfg(not(unix))]
                    continue;
                } else {
                    std::fs::hard_link(root.join("src/foo.RS"), root.join(reported)).unwrap();
                }
            }
            if reported == "src/linked.rs" {
                #[cfg(unix)]
                std::os::unix::fs::symlink(root.join("src/foo.RS"), root.join(reported)).unwrap();
                #[cfg(not(unix))]
                continue;
            }
            if reported != "src/linked.rs" {
                write(&root, reported, "pub fn after() {}\n");
            }
            let warm = warm.update(&BTreeSet::from([ProjectFile::new(&root, reported)]));
            let fresh = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.clone(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let warm = warm.store().unwrap().read_conn().unwrap();
            let fresh = fresh.store().unwrap().read_conn().unwrap();
            assert_eq!(
                live_crate_rows(&warm),
                live_crate_rows(&fresh),
                "reported={reported} hidden={hidden} second={second_link}"
            );
            if hidden {
                let expected =
                    git2::Oid::hash_object(git2::ObjectType::Blob, b"pub fn after() {}\n")
                        .unwrap()
                        .to_string();
                for path in ["src/foo.RS"]
                    .into_iter()
                    .chain(second_link.then_some("src/other.rs"))
                {
                    let oid: String = warm.query_row("SELECT blob_oid FROM workspace_file_versions WHERE rel_path = ?1 AND valid_until IS NULL ORDER BY valid_from DESC LIMIT 1", [path], |row| row.get(0)).unwrap();
                    assert_eq!(oid, expected);
                }
                let phantom: i64 = warm
                    .query_row(
                        "SELECT count(*) FROM rust_crate_file_naming WHERE rel_path = ?1",
                        [reported],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(phantom, 0);
            }
            if hidden {
                let phantom: i64 = warm
                    .query_row(
                        "SELECT count(*) FROM workspace_file_versions WHERE rel_path = ?1",
                        [reported],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(phantom, 0);
            }
        }
    }

    #[test]
    #[hardwon("#11231: a workspace update dropped an ignored JVM toolchain configuration edit")]
    fn update_workspace_admits_ignored_native_configuration_input() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        let java_revision = |workspace: &WorkspaceAnalyzer| {
            let WorkspaceAnalyzer::Multi(multi) = workspace else {
                panic!("Java workspace missing");
            };
            multi
                .delegates()
                .get(&Language::Java)
                .expect("Java delegate")
                .analyzer()
                .selected_workspace_snapshots_for_reads()
                .expect("Java snapshots")
                .values()
                .next()
                .expect("Java snapshot")
                .revision
        };
        for git_repository in [false, true] {
            let builder = InlineTestProject::with_language(Language::Java)
                .file("Sample.java", "class Sample {}\n")
                .file(
                    ".bifrost/jvm-toolchains.json",
                    "{\"schema_version\":1,\"source_toolchains\":[{\"source_root\":\"src\",\"jdk_home\":\"jdk-a\"}]}\n",
                )
                .file(".gitignore", ".bifrost/\n");
            // A Git-backed enumeration keeps the ignored directory traversable.
            // A plain directory walk prunes the directory with its contents.
            let fixture = if git_repository {
                builder.with_git().build()
            } else {
                builder.build()
            };
            let config = fixture.file(".bifrost/jvm-toolchains.json");
            let warm = fixture.workspace_analyzer(AnalyzerConfig::default());
            let initial = java_revision(&warm);
            config
                .write("{\"schema_version\":1,\"source_toolchains\":[{\"source_root\":\"src\",\"jdk_home\":\"jdk-b\"}]}\n")
                .unwrap();
            let warm = warm.update(&BTreeSet::from([config.clone()]));
            assert_eq!(
                java_revision(&warm),
                initial + 1,
                "the ignored toolchain edit must advance the Java revision (git={git_repository})"
            );
            assert!(
                !fixture.project().all_files().unwrap().contains(&config),
                "the toolchain input must stay out of the source listing (git={git_repository})"
            );
        }
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks external path targets can belong to multiple nearest crate roots while manual bins own themselves."
    )]
    fn cargo_target_membership_crosses_nearest_manifest_boundaries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"shared\", \"runner\"]\nresolver = \"2\"\n",
        );
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(
            &root,
            "app/src/lib.rs",
            "#[path = \"../../shared/src/model.rs\"]\nmod imported;\n",
        );
        write(
            &root,
            "shared/Cargo.toml",
            "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "shared/src/lib.rs", "mod model;\n");
        write(&root, "shared/src/model.rs", "pub struct Model;\n");
        write(&root, "shared/tool.rs", "fn main() {}\n");
        write(
            &root,
            "runner/Cargo.toml",
            "[package]\nname = \"runner\"\nversion = \"0.1.0\"\nedition = \"2021\"\nautobins = false\n\n[[bin]]\nname = \"tool\"\npath = \"../shared/tool.rs\"\n",
        );

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let shared = ProjectFile::new(root.clone(), "shared/src/lib.rs");
        let model = ProjectFile::new(root.clone(), "shared/src/model.rs");
        let tool = ProjectFile::new(root.clone(), "shared/tool.rs");
        with_certified_rust_routes(&root, |rust| {
            let model_roots: HashSet<_> = rust
                .file_routes(&model, None)
                .unwrap()
                .target_roots(&model)
                .into_iter()
                .collect();
            assert_eq!(model_roots.len(), 2);
            assert!(model_roots.contains(&app));
            assert!(model_roots.contains(&shared));
            // #11033 item 2: an explicit Cargo target outside its manifest directory
            // is rejected by the selected inventory; retain an incomplete answer.
            let tool_routes = rust.file_routes(&tool, None).unwrap();
            assert!(!tool_routes.is_complete());
            assert!(tool_routes.target_roots(&tool).is_empty());
        });
    }
    #[test]
    fn path_dependency_routes_honor_library_name_aliases_and_ignore_registry_matches() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "matcher/Cargo.toml",
            "[package]\nname = \"matcher-package\"\nversion = \"0.1.0\"\n[lib]\nname = \"matcher_lib\"\n",
        );
        write(&root, "matcher/src/lib.rs", "pub struct Pattern;\n");
        write(
            &root,
            "consumer/Cargo.toml",
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nmatcher-package = { path = \"../matcher\" }\nregistry_alias = { package = \"matcher-package\", version = \"1\" }\n",
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        write(
            &root,
            "renamed/Cargo.toml",
            "[package]\nname = \"renamed\"\nversion = \"0.1.0\"\n[dependencies]\ncustom_alias = { package = \"matcher-package\", path = \"../matcher\" }\n",
        );
        write(&root, "renamed/src/lib.rs", "pub fn run() {}\n");

        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");
        let renamed = ProjectFile::new(root.clone(), "renamed/src/lib.rs");
        with_certified_rust_routes(&root, |rust| {
            assert_eq!(
                rust.file_routes(&consumer, None)
                    .unwrap()
                    .resolve_module_package(&consumer, "matcher_lib"),
                Some("matcher_lib".to_string())
            );
            assert_eq!(
                rust.file_routes(&consumer, None)
                    .unwrap()
                    .resolve_module_package(&consumer, "matcher_lib::nested"),
                Some("matcher_lib.nested".to_string())
            );
            assert_eq!(
                rust.file_routes(&renamed, None)
                    .unwrap()
                    .resolve_module_package(&renamed, "custom_alias"),
                Some("matcher_lib".to_string())
            );
            assert_eq!(
                rust.file_routes(&consumer, None)
                    .unwrap()
                    .resolve_module_package(&consumer, "registry_alias"),
                None
            );
            assert_eq!(
                rust.file_routes(&consumer, None)
                    .unwrap()
                    .resolve_module_package(&consumer, "matcher_package"),
                None
            );
        });
    }
    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks inherited normal and dev dependencies route to the corresponding member targets."
    )]
    fn workspace_inherited_dependencies_keep_member_dependency_classes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"dependency\"]\nresolver = \"2\"\n\n[workspace.dependencies]\ninherited_normal = { package = \"workspace-dependency\", path = \"dependency\" }\ninherited_dev = { package = \"workspace-dependency\", path = \"dependency\" }\n",
        );
        write(
            &root,
            "dependency/Cargo.toml",
            "[package]\nname = \"workspace-dependency\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "dependency/src/lib.rs", "pub struct Shared;\n");
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ntest = false\n\n[dependencies]\ninherited_normal = { workspace = true }\n\n[dev-dependencies]\ninherited_dev = { workspace = true }\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");
        write(&root, "app/tests/integration.rs", "fn test() {}\n");

        let dependency = ProjectFile::new(root.clone(), "dependency/src/lib.rs");
        let library = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let test = ProjectFile::new(root.clone(), "app/tests/integration.rs");
        with_certified_rust_routes(&root, |rust| {
            assert_eq!(
                rust.file_routes(&library, None)
                    .unwrap()
                    .resolve_crate_root_file(&library, "inherited_normal"),
                Some(dependency.clone())
            );
            assert_eq!(
                rust.file_routes(&library, None)
                    .unwrap()
                    .resolve_crate_root_file(&library, "inherited_dev"),
                None
            );
            assert_eq!(
                rust.file_routes(&test, None)
                    .unwrap()
                    .resolve_crate_root_file(&test, "inherited_dev"),
                Some(dependency)
            );
        });
    }
    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks normal, dev, build, and target-specific dependency routing and duplicate destinations."
    )]
    fn dependency_kinds_are_scoped_to_compatible_cargo_targets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"normal\", \"development\", \"build-dep\", \"target-normal\", \"target-dev\", \"target-build\"]\nresolver = \"2\"\n",
        );
        for (directory, package) in [
            ("normal", "normal-package"),
            ("development", "development-package"),
            ("build-dep", "build-package"),
            ("target-normal", "target-normal-package"),
            ("target-dev", "target-dev-package"),
            ("target-build", "target-build-package"),
        ] {
            write(
                &root,
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{directory}/src/lib.rs"),
                "pub struct Shared;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"no-test\"\npath = \"src/bin/no_test.rs\"\ntest = false\n\n[dependencies]\nnormal_dep = { package = \"normal-package\", path = \"../normal\" }\noverlap = { package = \"normal-package\", path = \"../normal\" }\n\n[dev-dependencies]\ndev_dep = { package = \"development-package\", path = \"../development\" }\noverlap = { package = \"normal-package\", path = \"../normal\" }\n\n[build-dependencies]\nbuild_dep = { package = \"build-package\", path = \"../build-dep\" }\n\n[target.'cfg(unix)'.dependencies]\ntarget_normal = { package = \"target-normal-package\", path = \"../target-normal\" }\n\n[target.'cfg(unix)'.dev-dependencies]\ntarget_dev = { package = \"target-dev-package\", path = \"../target-dev\" }\n\n[target.'cfg(unix)'.build-dependencies]\ntarget_build = { package = \"target-build-package\", path = \"../target-build\" }\n",
        );
        write(&root, "app/src/lib.rs", "mod shared;\n");
        write(&root, "app/src/main.rs", "fn main() {}\n");
        write(&root, "app/src/bin/no_test.rs", "fn main() {}\n");
        write(&root, "app/src/shared.rs", "pub struct Local;\n");
        write(&root, "app/examples/demo.rs", "fn main() {}\n");
        write(
            &root,
            "app/tests/integration.rs",
            "#[path = \"../src/shared.rs\"]\nmod shared;\n",
        );
        write(&root, "app/benches/bench.rs", "fn main() {}\n");
        write(&root, "app/build.rs", "fn main() {}\n");

        let library = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let binary = ProjectFile::new(root.clone(), "app/src/main.rs");
        let no_test_binary = ProjectFile::new(root.clone(), "app/src/bin/no_test.rs");
        let shared = ProjectFile::new(root.clone(), "app/src/shared.rs");
        let example = ProjectFile::new(root.clone(), "app/examples/demo.rs");
        let test = ProjectFile::new(root.clone(), "app/tests/integration.rs");
        let bench = ProjectFile::new(root.clone(), "app/benches/bench.rs");
        let build = ProjectFile::new(root.clone(), "app/build.rs");
        with_certified_rust_routes(&root, |rust| {
            let normal_root = ProjectFile::new(root.clone(), "normal/src/lib.rs");
            let development_root = ProjectFile::new(root.clone(), "development/src/lib.rs");
            let build_root = ProjectFile::new(root.clone(), "build-dep/src/lib.rs");
            let target_normal_root = ProjectFile::new(root.clone(), "target-normal/src/lib.rs");
            let target_dev_root = ProjectFile::new(root.clone(), "target-dev/src/lib.rs");
            let target_build_root = ProjectFile::new(root.clone(), "target-build/src/lib.rs");

            for target in [
                &library,
                &binary,
                &no_test_binary,
                &example,
                &test,
                &bench,
                &shared,
            ] {
                assert_eq!(
                    rust.file_routes(target, None)
                        .unwrap()
                        .resolve_crate_root_file(target, "normal_dep"),
                    Some(normal_root.clone()),
                    "normal dependency from {}",
                    target.rel_path().display()
                );
                assert_eq!(
                    rust.file_routes(target, None)
                        .unwrap()
                        .resolve_crate_root_file(target, "target_normal"),
                    Some(target_normal_root.clone()),
                    "target-specific normal dependency from {}",
                    target.rel_path().display()
                );
            }
            assert_eq!(
                rust.file_routes(&build, None)
                    .unwrap()
                    .resolve_crate_root_file(&build, "normal_dep"),
                None
            );
            assert_eq!(
                rust.file_routes(&build, None)
                    .unwrap()
                    .resolve_crate_root_file(&build, "target_normal"),
                None
            );

            for target in [&library, &binary, &example, &test, &bench, &shared] {
                assert_eq!(
                    rust.file_routes(target, None)
                        .unwrap()
                        .resolve_crate_root_file(target, "dev_dep"),
                    Some(development_root.clone()),
                    "development dependency from {}",
                    target.rel_path().display()
                );
                assert_eq!(
                    rust.file_routes(target, None)
                        .unwrap()
                        .resolve_crate_root_file(target, "target_dev"),
                    Some(target_dev_root.clone()),
                    "target-specific development dependency from {}",
                    target.rel_path().display()
                );
            }
            // Cargo never compiles a test=false binary as a test. Production
            // rust_unit_summaries.rs development_capable uses the target test flag.
            for name in ["dev_dep", "target_dev"] {
                assert_eq!(
                    rust.file_routes(&no_test_binary, None)
                        .unwrap()
                        .resolve_crate_root_file(&no_test_binary, name),
                    None
                );
            }
            assert_eq!(
                rust.file_routes(&build, None)
                    .unwrap()
                    .resolve_crate_root_file(&build, "dev_dep"),
                None
            );
            assert_eq!(
                rust.file_routes(&build, None)
                    .unwrap()
                    .resolve_crate_root_file(&build, "target_dev"),
                None
            );

            assert_eq!(
                rust.file_routes(&build, None)
                    .unwrap()
                    .resolve_crate_root_file(&build, "build_dep"),
                Some(build_root)
            );
            assert_eq!(
                rust.file_routes(&build, None)
                    .unwrap()
                    .resolve_crate_root_file(&build, "target_build"),
                Some(target_build_root)
            );
            for target in [
                &library,
                &binary,
                &no_test_binary,
                &example,
                &test,
                &bench,
                &shared,
            ] {
                assert_eq!(
                    rust.file_routes(target, None)
                        .unwrap()
                        .resolve_crate_root_file(target, "build_dep"),
                    None
                );
                assert_eq!(
                    rust.file_routes(target, None)
                        .unwrap()
                        .resolve_crate_root_file(target, "target_build"),
                    None
                );
            }
            assert_eq!(
                rust.file_routes(&example, None)
                    .unwrap()
                    .resolve_crate_root_file(&example, "overlap"),
                Some(normal_root),
                "identical normal/dev declarations must deduplicate by destination"
            );
            assert_eq!(
                rust.file_routes(&build, None)
                    .unwrap()
                    .resolve_crate_root_file(&build, "app"),
                None
            );
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks conflicting target destinations fail closed while a unique conditional route stays usable."
    )]
    fn target_specific_dependency_conflicts_fail_closed_by_destination() {
        // D18b partial-answer rule (#11033 item 1): incomplete units withhold
        // all forward targets, retain positive availability, and deny test-only.
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"left\", \"right\"]\nresolver = \"2\"\n",
        );
        for dependency in ["left", "right"] {
            write(
                &root,
                &format!("{dependency}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{dependency}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{dependency}/src/lib.rs"),
                "pub struct Shared;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstable = { package = \"left\", path = \"../left\" }\n\n[target.'cfg(unix)'.dependencies]\nconflict = { package = \"left\", path = \"../left\" }\nstable = { package = \"left\", path = \"../left\" }\nsingle = { package = \"left\", path = \"../left\" }\n\n[target.'cfg(windows)'.dependencies]\nconflict = { package = \"right\", path = \"../right\" }\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let left = ProjectFile::new(root.clone(), "left/src/lib.rs");

        with_certified_rust_routes(&root, |rust| {
            assert!(!rust.file_routes(&app, None).unwrap().is_complete());
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .has_available_declared_dependency(&app, "conflict"),
                None
            );
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "conflict"),
                None
            );
            // Fail-closed precision loss, #11033 item 1: a conflicting extern
            // name leaves a unit-wide gap: the positive single row survives,
            // but its forward route is lost.
            let routes = rust.file_routes(&app, None).unwrap();
            assert!(!routes.is_complete());
            assert_eq!(
                routes.has_available_declared_dependency(&app, "single"),
                Some(true)
            );
            assert_eq!(routes.resolve_crate_root_file(&app, "single"), None);
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "stable"),
                None,
                "incomplete units withhold every forward target"
            );
            assert!(
                rust.files_that_can_reference_target_of(&left, None)
                    .unwrap()
                    .value
                    .contains(&app),
                "the inverse candidate index must retain reachable dependency roots"
            );
        });
        // A unique conditional route without a conflicting sibling is complete.
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[target.'cfg(unix)'.dependencies]\nsingle={package='left',path='../left'}\n",
        );
        with_certified_rust_routes(&root, |rust| {
            let routes = rust.file_routes(&app, None).unwrap();
            assert!(routes.is_complete());
            assert_eq!(
                routes.resolve_crate_root_file(&app, "single"),
                Some(left.clone())
            );
        });
    }
    #[test]
    fn cargo_boundary_legacy_module_graph_matches_reachability() {
        // D18b partial-answer rule (#11033 item 3): incomplete routes retain
        // positive graph roots but conservatively deny every test-only answer.
        use brokk_bifrost_core::analyzer::ProjectFile;
        // A diamond shared by two Cargo roots. A separate cfg(test) branch has
        // a child without its own cfg; neither belongs to production reachability.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().expect("canonical root");
        let definitions = [
            (
                "Cargo.toml",
                "[package]\nname='graph'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nexternal-package='1'\ndirect={path='direct'}\n[patch.crates-io]\nexternal-package={path='patched'}\n",
            ),
            (
                "patched/Cargo.toml",
                "[package]\nname='external-package'\nversion='1.0.0'\nedition='2021'\n[lib]\nname='external_api'\n",
            ),
            ("patched/src/lib.rs", "pub struct Patched;"),
            (
                "direct/Cargo.toml",
                "[package]\nname='direct'\nversion='0.1.0'\nedition='2021'\n",
            ),
            ("direct/src/lib.rs", "pub struct Direct;"),
            (
                "nested-app/Cargo.toml",
                "[package]\nname='nested-app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nescape={path='../../..'}\n",
            ),
            ("nested-app/src/lib.rs", "pub struct Nested;"),
            ("src/lib.rs", "mod left; mod right; #[cfg(test)] mod tests;"),
            ("src/main.rs", "mod left; mod bin_only; fn main() {}"),
            ("src/left.rs", "#[path=\"shared.rs\"] mod shared;"),
            (
                "src/right.rs",
                "#[path=\"shared.rs\"] mod shared; mod tail;",
            ),
            (
                "src/shared.rs",
                "pub struct Shared; #[path=\"left.rs\"] mod back;",
            ),
            ("src/right/tail.rs", "pub struct Tail; mod deep;"),
            ("src/right/tail/deep.rs", "pub struct Deep; mod terminal;"),
            ("src/right/tail/deep/terminal.rs", "pub struct Terminal;"),
            ("src/bin_only.rs", "pub struct BinaryOnly;"),
            ("src/tests.rs", "mod helper;"),
            ("src/tests/helper.rs", "pub struct Helper;"),
        ];
        for (path, source) in definitions {
            write(&root, path, source);
        }
        // This table is the finite graph's independently derived transitive closure.
        let expected = [
            ("direct/src/lib.rs", &["direct/src/lib.rs"][..], false),
            (
                "nested-app/src/lib.rs",
                &["nested-app/src/lib.rs"][..],
                false,
            ),
            ("patched/src/lib.rs", &["patched/src/lib.rs"][..], false),
            ("src/lib.rs", &["src/lib.rs"][..], false),
            ("src/main.rs", &["src/main.rs"][..], false),
            ("src/left.rs", &["src/lib.rs", "src/main.rs"][..], false),
            ("src/right.rs", &["src/lib.rs"][..], false),
            ("src/shared.rs", &["src/lib.rs", "src/main.rs"][..], false),
            ("src/right/tail.rs", &["src/lib.rs"][..], false),
            ("src/right/tail/deep.rs", &["src/lib.rs"][..], false),
            (
                "src/right/tail/deep/terminal.rs",
                &["src/lib.rs"][..],
                false,
            ),
            ("src/bin_only.rs", &["src/main.rs"][..], false),
            // #11033 item 3: incomplete routes conservatively never narrow to test-only.
            ("src/tests.rs", &["src/lib.rs"][..], false),
            ("src/tests/helper.rs", &["src/lib.rs"][..], false),
        ];
        with_certified_rust_routes(&root, |rust| {
            let caller = ProjectFile::new(root.clone(), "src/lib.rs");
            let routes = rust.file_routes(&caller, None).unwrap();
            // #11033 item 3: the patched dependency fixture is incomplete.
            assert!(!routes.is_complete());
            assert_eq!(
                routes.resolve_crate_root_file(&caller, "external_api"),
                None
            );
            assert_eq!(
                routes.resolve_crate_root_file(&caller, "external_package"),
                None
            );
            let nested = ProjectFile::new(root.clone(), "nested-app/src/lib.rs");
            assert_eq!(
                rust.file_routes(&nested, None)
                    .unwrap()
                    .resolve_crate_root_file(&nested, "graph"),
                None,
                "an escaping dependency path cannot resolve to the workspace root"
            );
            for (path, roots, test_only) in expected {
                let file = ProjectFile::new(root.clone(), path);
                let routes = rust.file_routes(&file, None).unwrap();
                let mut actual = routes
                    .target_roots(&file)
                    .iter()
                    .map(|f| f.rel_path().to_string_lossy().replace('\\', "/"))
                    .collect::<Vec<_>>();
                actual.sort();
                assert_eq!(roots, actual, "{path}");
                assert_eq!(test_only, routes.file_is_test_only(&file), "{path}");
            }
        });
    }

    fn dependency_route_fixture(manifest: &str) -> BuiltInlineTestProject {
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['app','left','right']\nresolver='2'\n",
            )
            .file(
                "app/Cargo.toml",
                format!("[package]\nname='app'\nversion='0.1.0'\nedition='2021'\nautobins=false\n[[bin]]\nname='app'\npath='src/main.rs'\ntest=false\nbench=false\n{manifest}"),
            )
            .file("app/src/lib.rs", "pub struct App;")
            .file("app/src/main.rs", "fn main() {}")
            .file("app/tests/check.rs", "#[test] fn check() {}")
            .file(
                "left/Cargo.toml",
                "[package]\nname='left'\nversion='0.1.0'\n[lib]\nname='left_lib'\n",
            )
            .file("left/src/lib.rs", "pub struct Left;")
            .file(
                "right/Cargo.toml",
                "[package]\nname='right'\nversion='0.1.0'\n",
            )
            .file("right/src/lib.rs", "pub struct Right;")
            .build()
    }

    fn check_dependency_routes(
        project: &BuiltInlineTestProject,
        path: &str,
        expected: &[(&str, Option<&str>)],
        complete: bool,
    ) {
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let listing =
            std::sync::Arc::new(WorkspaceFileListingCache::new(project.root().to_path_buf()));
        let filesystem = std::sync::Arc::new(
            FilesystemProject::with_cached_listing(project.root(), listing).unwrap(),
        );
        let analyzer =
            brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_persisted(
                filesystem,
                AnalyzerConfig::default(),
            )
            .unwrap();
        check_analyzer_dependency_routes(&analyzer, project.root(), path, expected, complete);
    }

    fn check_analyzer_dependency_routes(
        analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        root: &std::path::Path,
        path: &str,
        expected: &[(&str, Option<&str>)],
        complete: bool,
    ) {
        use brokk_bifrost_core::analyzer::{ProjectFile, model::Language};
        use brokk_bifrost_rust::graph_support::RustSource;
        let brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::Multi(multi) = analyzer
        else {
            panic!("Rust workspace missing")
        };
        let rust = multi.delegates().get(&Language::Rust).unwrap().analyzer();
        let rust = (rust as &dyn std::any::Any)
            .downcast_ref::<brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer>()
            .unwrap();
        let file = ProjectFile::new(root.to_path_buf(), path);
        let routes = rust.file_routes(&file, None).unwrap();
        assert_eq!(routes.is_complete(), complete);
        for (name, destination) in expected {
            assert_eq!(
                routes.resolve_crate_root_file(&file, name),
                destination.map(|path| ProjectFile::new(root.to_path_buf(), path)),
                "{name}"
            );
            assert_eq!(
                routes.resolve_module_package(&file, name).is_some(),
                destination.is_some(),
                "package {name}"
            );
            if !complete && destination.is_none() {
                assert_eq!(
                    routes.has_available_declared_dependency(&file, name),
                    None,
                    "{name} is unknown"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#10953: producer dropped conditional dependencies and certified conflicting destinations absent"
    )]
    fn producer_conditional_dependency_destinations() {
        let unique = dependency_route_fixture(
            "[target.'cfg(unix)'.dependencies]\nsingle={package='left',path='../left'}\n",
        );
        check_dependency_routes(
            &unique,
            "app/src/lib.rs",
            &[("single", Some("left/src/lib.rs"))],
            true,
        );
        let conflict = dependency_route_fixture(
            "[target.'cfg(unix)'.dependencies]\nconflict={package='left',path='../left'}\n[target.'cfg(windows)'.dependencies]\nconflict={package='right',path='../right'}\n",
        );
        check_dependency_routes(&conflict, "app/src/lib.rs", &[("conflict", None)], false);
        for manifest in [
            "[target.'cfg(unix)']\ndependencies=7\n",
            "[target.'cfg(unix)'.dependencies]\nbroken=7\n",
        ] {
            let malformed = dependency_route_fixture(manifest);
            check_dependency_routes(&malformed, "app/src/lib.rs", &[("broken", None)], false);
        }
    }

    #[test]
    #[hardwon("#10953: producer dropped target-scoped normal and dev dependency kinds")]
    fn producer_conditional_dependency_kinds() {
        let project = dependency_route_fixture(
            "[target.'cfg(unix)'.dependencies]\nnormal={package='left',path='../left'}\n[target.'cfg(unix)'.dev-dependencies]\ndev={package='right',path='../right'}\n",
        );
        check_dependency_routes(
            &project,
            "app/src/lib.rs",
            &[("normal", Some("left/src/lib.rs"))],
            true,
        );
        check_dependency_routes(
            &project,
            "app/src/main.rs",
            &[("normal", Some("left/src/lib.rs")), ("dev", None)],
            true,
        );
        check_dependency_routes(
            &project,
            "app/tests/check.rs",
            &[
                ("normal", Some("left/src/lib.rs")),
                ("dev", Some("right/src/lib.rs")),
            ],
            true,
        );
    }

    #[test]
    #[hardwon("#10953: producer bound unrenamed path dependency by key instead of library name")]
    fn producer_dependency_library_name() {
        let project = dependency_route_fixture("[dependencies]\nleft={path='../left'}\n");
        check_dependency_routes(
            &project,
            "app/src/lib.rs",
            &[("left_lib", Some("left/src/lib.rs")), ("left", None)],
            true,
        );
    }

    #[test]
    #[hardwon(
        "#10953: warm stores retained dropped target-table dependencies and key-named path dependencies across producer upgrade"
    )]
    fn warm_dependency_name_upgrade_rederives_crates() {
        if run_derivation_version_child() {
            return;
        }
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        // One store holds all three old wrong answers: an unrenamed path
        // dependency published under its key, and target-table normal and
        // dev dependencies the old producer never wrote.
        let project = dependency_route_fixture(
            "[dependencies]\nleft={path='../left'}\n[target.'cfg(unix)'.dependencies]\nsingle={package='right',path='../right'}\n[target.'cfg(unix)'.dev-dependencies]\ndev={package='right',path='../right'}\n",
        );
        let listing =
            std::sync::Arc::new(WorkspaceFileListingCache::new(project.root().to_path_buf()));
        let filesystem = std::sync::Arc::new(
            FilesystemProject::with_cached_listing(project.root(), listing).unwrap(),
        );
        let build =
            || WorkspaceAnalyzer::build_persisted(filesystem.clone(), AnalyzerConfig::default());
        let old = RUST_CRATE_DERIVATION_VERSION
            .split_once("-10953-target-dependencies-and-lib-names")
            .map_or(RUST_CRATE_DERIVATION_VERSION, |(old, _)| old);
        set_derivation_version(Some(old));
        let first = build();
        set_derivation_version(None);
        let first = first.unwrap();
        first
            .store()
            .unwrap()
            .conn
            .execute_fixture(|conn| {
                conn.execute_batch(
            "UPDATE rust_crate_dependencies SET extern_name='left' WHERE extern_name='left_lib';
             DELETE FROM rust_crate_dependencies WHERE extern_name IN ('single','dev');
             DELETE FROM rust_resolution_unit_summary_versions;
             DELETE FROM resolution_unit_summary_versions WHERE lang='rust';
             DELETE FROM resolution_unit_summaries WHERE lang='rust';"
        )
            })
            .unwrap();
        let snapshot = first
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| {
                    Ok(WorkspaceSnapshotId {
                        workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(
                            row.get(0)?,
                        ),
                        lang: "rust".into(),
                        generation:
                            brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                                row.get(1)?,
                            ),
                        revision: row.get(2)?,
                    })
                },
            )
            .unwrap();
        set_derivation_version(Some(old));
        let summaries = first
            .store()
            .unwrap()
            .reconcile_rust_unit_summaries(&snapshot);
        set_derivation_version(None);
        assert!(summaries.unwrap().failed.is_empty());
        let names = |analyzer: &WorkspaceAnalyzer| {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .prepare(
                    "SELECT DISTINCT d.extern_name FROM rust_crate_dependencies d
                 JOIN rust_crate_versions v USING(topology_id)
                 WHERE v.valid_until IS NULL AND d.extern_name IN ('left','left_lib','single','dev') ORDER BY 1",
                )
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(names(&first), ["left"]);
        drop(first);
        let upgraded = build().unwrap();
        assert_eq!(
            names(&upgraded),
            ["dev", "left_lib", "single"],
            "warm upgrade must replace old wrong dependency rows"
        );
        check_analyzer_dependency_routes(
            &upgraded,
            project.root(),
            "app/src/lib.rs",
            &[
                ("left_lib", Some("left/src/lib.rs")),
                ("left", None),
                ("single", Some("right/src/lib.rs")),
            ],
            true,
        );
        check_analyzer_dependency_routes(
            &upgraded,
            project.root(),
            "app/tests/check.rs",
            &[("dev", Some("right/src/lib.rs"))],
            true,
        );
    }

    // The store override is process-wide, including background writers. Run
    // each override test alone in a child harness so ordinary workspace builds
    // in the parent process always see the real derivation version.
    fn run_derivation_version_child() -> bool {
        const CHILD_TEST: &str = "BIFROST_DERIVATION_VERSION_CHILD_TEST";
        let thread = std::thread::current();
        let name = thread
            .name()
            .expect("libtest names the running test thread");
        if std::env::var(CHILD_TEST).as_deref() == Ok(name) {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD_TEST, name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated derivation-version test {name} failed: {output:?}"
        );
        true
    }

    /// Rewrite a revision's certificate in place. The store never does this: a
    /// revision's certificate never changes. A fixture does it to stand in for
    /// a revision that was certified under another derivation version, or
    /// whose listing could not be read, which no build produces.
    pub(in crate::engine_tests) fn overwrite_rust_listing_certificate(
        store: &AnalyzerStore,
        snapshot: &WorkspaceSnapshotId,
        version: i64,
        failures: Vec<(String, String)>,
    ) {
        let snapshot = snapshot.clone();
        store.conn.execute_fixture(move |conn| {
            let key = params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision
            ];
            conn.execute(
                "DELETE FROM rust_source_listing_certificates
                 WHERE workspace_id=?1 AND lang='rust' AND generation=?2 AND revision=?3",
                key,
            )
            .unwrap();
            conn.execute(
                "INSERT INTO rust_source_listing_certificates
                 (workspace_id,lang,generation,revision,derivation_version,complete)
                 VALUES (?1,'rust',?2,?3,?4,?5)",
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    snapshot.revision,
                    version,
                    failures.is_empty()
                ],
            )
            .unwrap();
            for (path, reason) in failures {
                conn.execute(
                    "INSERT INTO rust_source_listing_failures
                     (workspace_id,lang,generation,revision,rel_path,reason)
                     VALUES (?1,'rust',?2,?3,?4,?5)",
                    params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.0,
                        snapshot.revision,
                        path,
                        reason
                    ],
                )
                .unwrap();
            }
        });
    }

    #[test]
    fn crate_path_probes_cover_walk_and_naming_inputs() {
        for name in ["Foo", "foo"] {
            let source = format!(
                "mod {name}; mod placed; #[path = \"other.rs\"] mod other; include!(\"gen.inc\");"
            );
            let project = InlineTestProject::new()
                .file("Cargo.toml", "[package]\nname = \"probes\"\nversion = \"0.1.0\"\nedition = \"2021\"\nautoexamples = false\n")
                .file("src/lib.rs", &source)
                .file("src/placed.rs", "pub fn placed() {}")
                .file("src/other.rs", "pub fn other() {}")
                .file("src/gen.inc", "pub fn generated() {}")
                .file("examples/demo/helper.rs", "pub fn helper() {}")
                .build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            let probes = conn.prepare("SELECT probe_key FROM rust_crate_path_probes JOIN rust_crate_topologies USING(topology_id) WHERE target_kind='lib'").unwrap()
                .query_map([], |row| row.get::<_, String>(0)).unwrap()
                .collect::<rusqlite::Result<BTreeSet<_>>>().unwrap();
            for path in [
                "src/lib.rs",
                "src/foo.rs",
                "src/foo/mod.rs",
                "src/placed.rs",
                "src/placed/mod.rs",
                "src/other.rs",
                "src/gen.inc",
            ] {
                assert!(probes.contains(path), "missing {path}: {probes:?}");
            }
            let naming: i64 = conn.query_row("SELECT count(*) FROM rust_crate_path_probes WHERE probe_key='examples/demo/main.rs'", [], |row| row.get(0)).unwrap();
            assert!(naming > 0, "detached members record their naming probe");
            assert!(
                live_crate_rows(&conn)
                    .iter()
                    .any(|(table, rows)| table == "rust_crate_path_probes" && !rows.is_empty())
            );
        }
    }

    fn fixture() -> BuiltInlineTestProject {
        InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"app\", \"dep\", \"helper\"]\nresolver = \"2\"\n")
            .file("app/Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ndep = { path = \"../dep\", features = [\"on\"] }\n[dev-dependencies]\nhelper = { path = \"../helper\" }\n")
            .file("dep/Cargo.toml", "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\non = []\noff = []\n")
            .file("helper/Cargo.toml", "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("app/src/lib.rs", r#"
                pub mod a;
                #[path = "shared.rs"] mod shared;
                pub mod m { pub fn inside() {} }
                #[cfg(test)] mod tests { pub fn test_only() {} }
                pub use a::*;
                pub use a::original as b;
                pub use a::b as first;
                pub use first as second;
                pub use second as third;
                pub use dep::X;
                use crate::a::{b as c};
            "#)
            .file("app/src/main.rs", "#[path = \"shared.rs\"] mod shared; fn main() {}")
            .file("app/src/shared.rs", "pub fn shared() {}")
            .file("app/src/a.rs", "use super::*; pub fn b() { let body = 1; } pub fn original() {}")
            .file("app/tests/x.rs", "use helper::H; #[test] fn x() {}")
            .file("dep/src/lib.rs", "pub struct X(pub u8); #[cfg(feature = \"on\")] pub mod on; #[cfg(feature = \"off\")] pub mod off;")
            .file("dep/src/on.rs", "pub fn enabled() {}")
            .file("dep/src/off.rs", "pub fn disabled() {}")
            .file("helper/src/lib.rs", "pub struct H;")
            .file("detached.rs", "pub fn detached() {}")
            .build()
    }

    #[test]
    #[hardwon(
        "#9918: a glob cycle and its alias chain made valid same-crate re-exports unresolved imports"
    )]
    fn rust_summary_local_glob_cycle_imports() {
        let cases = [
            ("none", "", true),
            ("path module", "#[path = \"shared.rs\"] mod shared;", true),
            (
                "test module",
                "#[cfg(test)] mod tests { pub fn test_only() {} }",
                true,
            ),
            ("glob cycle", "pub use a::*;", true),
            (
                "alias chain",
                "pub use a::original as b; pub use a::b as first; pub use first as second; pub use second as third;",
                true,
            ),
            ("dependency", "pub use dep::X;", true),
            ("inline module", "pub mod m { pub fn inside() {} }", true),
            ("missing import", "pub use a::missing;", false),
            (
                "sibling alias",
                "mod one { pub use crate::a::b as first; } mod two { pub use first as second; }",
                false,
            ),
            ("non-root glob cycle", "pub mod m; pub mod n;", true),
            ("2015 non-root import", "pub mod m;", true),
            ("extern shadows root name", "pub mod x; pub mod m;", true),
        ];
        for (name, extra, expected_complete) in cases {
            let edition = if name == "2015 non-root import" {
                "2015"
            } else {
                "2021"
            };
            let dependency = if name == "extern shadows root name" {
                "x"
            } else {
                "dep"
            };
            let m_source = match name {
                "non-root glob cycle" => "pub use crate::n::*; pub fn m_fn() {}",
                "2015 non-root import" => "use a::b; pub fn m_fn() {}",
                "extern shadows root name" => "use x::Y; pub fn m_fn() {}",
                _ => "",
            };
            let project = InlineTestProject::new()
                .file("Cargo.toml", "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n")
                .file("app/Cargo.toml", format!("[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"{edition}\"\n[dependencies]\n{dependency}={{package=\"dep\",path=\"../dep\"}}\n"))
                .file("dep/Cargo.toml", "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
                .file("app/src/lib.rs", format!("pub mod a; {extra}"))
                .file("app/src/a.rs", "use super::*; pub fn b() {} pub fn original() {}")
                .file("app/src/shared.rs", "pub fn shared() {}")
                .file("app/src/m.rs", m_source)
                .file("app/src/n.rs", "pub use crate::m::*; pub fn n_fn() {}")
                .file("app/src/x.rs", "pub struct Y;")
                .file("dep/src/lib.rs", "pub struct X; pub struct Y;")
                .build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            let (complete, gaps): (bool, String) = conn.query_row(
                "SELECT summary.complete, COALESCE(group_concat(gap.gap_kind || ':' || gap.subject), '')
                 FROM resolution_unit_summary_versions AS version
                 JOIN resolution_unit_summaries AS summary USING(summary_id)
                 JOIN rust_resolution_unit_summary_contexts AS context USING(summary_id)
                 LEFT JOIN resolution_unit_summary_gaps AS gap USING(summary_id)
                 WHERE version.valid_until IS NULL AND context.crate_name='app'
                 GROUP BY summary.summary_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            assert_eq!(complete, expected_complete, "{name}: {gaps}");
            if name == "extern shadows root name" {
                let external_imports: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM resolution_unit_summary_imports AS imports
                     JOIN source_import_segments AS segment
                       ON segment.blob_id=imports.blob_id AND segment.import_id=imports.import_id
                     WHERE segment.segment='Y' AND imports.state='resolved'
                       AND imports.dependency_ordinal IS NOT NULL",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(
                    external_imports, 1,
                    "{name}: x::Y must bind to the dependency"
                );
            }
            assert_eq!(
                gaps.contains("unresolved_import"),
                !expected_complete,
                "{name}: {gaps}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#9918: the dep crate was incomplete, so the parity guard skipped it and hid the inactive-placement gap"
    )]
    fn keyed_rust_route_reads_match_whole_summary_rows() {
        use brokk_bifrost_analysis::analyzer::derivation_host::{
            AnalyzerDerivations, UnitSummaryKind,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::{
            rust_crate_name_units, rust_file_units, rust_package_units, rust_unit_dependents,
        };
        use brokk_bifrost_core::CancellationToken;
        use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::{
            RustCrateNameUnits, RustFileUnits, RustPackageUnits, RustTargetReachability,
            RustUnitDependents, RustUnitInputs, RustUnitRoutes, SelectedRustUnit,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            Demanded, DerivationKind, Handle,
        };
        let project = fixture();
        // Unrelated Cargo roots distinguish a name seek from walking live units.
        let manifest = std::fs::read_to_string(project.root().join("Cargo.toml")).unwrap();
        std::fs::write(
            project.root().join("Cargo.toml"),
            manifest.replace("\"helper\"]", "\"helper\", \"noise*\"]"),
        )
        .unwrap();
        for i in 0..12 {
            write(
                project.root(),
                &format!("noise{i}/Cargo.toml"),
                &format!("[package]\nname='noise{i}'\nversion='0.1.0'\n"),
            );
            write(
                project.root(),
                &format!("noise{i}/src/lib.rs"),
                "pub fn noise() {}\n",
            );
        }
        let manifest_path = project.root().join("app/Cargo.toml");
        let manifest = std::fs::read_to_string(&manifest_path).unwrap();
        std::fs::write(
            manifest_path,
            manifest.replace("dep = { path", "renamed_dep = { package = \"dep\", path"),
        )
        .unwrap();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let (workspace, generation, revision) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let snapshots =
            std::iter::once(("rust".into(), snapshot.clone())).collect::<WorkspaceSnapshots>();
        let inventory = match store
            .open_selected_resolution_mount_inventory(
                &snapshot.workspace_id,
                &snapshots,
                &[SelectedResolutionLanguage::new(
                    "rust".to_string(),
                    Language::Rust,
                )],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(i) => i,
            _ => panic!("selection unavailable"),
        };
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        let keys=inventory.connection().prepare("SELECT DISTINCT unit_key FROM resolution_unit_summary_versions WHERE workspace_id=?1 AND lang='rust' AND generation=?2 AND valid_from<=?3 AND (valid_until IS NULL OR ?3<valid_until)").unwrap().query_map(params![snapshot.workspace_id.as_str(),snapshot.generation.0,snapshot.revision],|r|r.get::<_,Vec<u8>>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let mut expected_files = std::collections::BTreeMap::<String, Vec<[u8; 32]>>::new();
        let mut expected_deps =
            std::collections::BTreeMap::<[u8; 32], Vec<([u8; 32], String)>>::new();
        let mut expected_packages =
            std::collections::BTreeMap::<String, Vec<([u8; 32], u32)>>::new();
        let mut expected_names =
            std::collections::BTreeMap::<String, Vec<([u8; 32], String, String)>>::new();
        let mut reachable_units = 0;
        for raw in keys {
            let unit: [u8; 32] = raw.try_into().unwrap();
            match host.demand::<RustUnitRoutes>(
                analyzer.analyzer(),
                &inventory,
                &SelectedRustUnit::minted_by_test_fixture(unit, true),
            ) {
                Demanded::Available { .. } => {
                    let recomputed = host.counters(RustUnitRoutes::ID).recomputed;
                    assert!(matches!(
                        host.demand::<RustUnitRoutes>(
                            analyzer.analyzer(),
                            &inventory,
                            &SelectedRustUnit::minted_by_test_fixture(unit, true)
                        ),
                        Demanded::Available {
                            value: Handle::Retained(_),
                            ..
                        }
                    ));
                    assert_eq!(host.counters(RustUnitRoutes::ID).recomputed, recomputed);
                    if let Demanded::Available { value, .. } = host
                        .demand::<RustTargetReachability>(
                            analyzer.analyzer(),
                            &inventory,
                            &SelectedRustUnit::minted_by_test_fixture(unit, true),
                        )
                    {
                        let rows = AnalyzerStore::rust_summary_cargo_route_rows_for_unit(
                            inventory.connection(),
                            &snapshot,
                            &unit,
                        )
                        .unwrap();
                        let roots = rows
                            .iter()
                            .filter(|row| row.target_kind != "detached")
                            .filter_map(|row| row.root_rel_path.clone())
                            .map(|path| ProjectFile::new(project.root().to_path_buf(), path))
                            .collect::<HashSet<_>>();
                        let mut expected = Vec::new();
                        for root in &roots {
                            expected.extend(
                                // Slash-separated, so the keys also match on Windows.
                                match brokk_bifrost_core::path_utils::rel_path_string(root)
                                    .as_str()
                                {
                                    "app/src/lib.rs" => vec![
                                        "app/src/a.rs",
                                        "app/src/lib.rs",
                                        "app/src/main.rs",
                                        "app/src/shared.rs",
                                        "app/tests/x.rs",
                                    ],
                                    "app/src/main.rs" => {
                                        vec!["app/src/main.rs", "app/src/shared.rs"]
                                    }
                                    "app/tests/x.rs" => vec!["app/tests/x.rs"],
                                    "dep/src/lib.rs" => vec![
                                        "app/src/a.rs",
                                        "app/src/lib.rs",
                                        "app/src/main.rs",
                                        "app/src/shared.rs",
                                        "app/tests/x.rs",
                                        "dep/src/lib.rs",
                                        "dep/src/off.rs",
                                        "dep/src/on.rs",
                                    ],
                                    "helper/src/lib.rs" => vec![
                                        "app/src/a.rs",
                                        "app/src/lib.rs",
                                        "app/src/main.rs",
                                        "app/src/shared.rs",
                                        "app/tests/x.rs",
                                        "helper/src/lib.rs",
                                    ],
                                    other if other.starts_with("noise") => vec![other],
                                    other => panic!("unexpected fixture root {other}"),
                                }
                                .into_iter()
                                .map(str::to_owned),
                            );
                        }
                        expected.sort_unstable();
                        expected.dedup();
                        let mut paths = value
                            .roots
                            .iter()
                            .flat_map(|entry| entry.files.iter().cloned())
                            .collect::<Vec<_>>();
                        paths.sort_unstable();
                        paths.dedup();
                        assert_eq!(&paths, &expected, "unit={unit:?}, roots={roots:?}");
                        let recomputed = host.counters(RustTargetReachability::ID).recomputed;
                        assert!(matches!(
                            host.demand::<RustTargetReachability>(
                                analyzer.analyzer(),
                                &inventory,
                                &SelectedRustUnit::minted_by_test_fixture(unit, true)
                            ),
                            Demanded::Available {
                                value: Handle::Retained(_),
                                ..
                            }
                        ));
                        assert_eq!(
                            host.counters(RustTargetReachability::ID).recomputed,
                            recomputed
                        );
                        reachable_units += 1;
                    }
                }
                Demanded::Unavailable(_) => {
                    assert!(matches!(
                        host.demand::<RustTargetReachability>(
                            analyzer.analyzer(),
                            &inventory,
                            &SelectedRustUnit::minted_by_test_fixture(unit, true)
                        ),
                        Demanded::Unavailable(_)
                    ));
                }
            }
            let summary_id: i64 = inventory.connection().query_row(
                "SELECT summary_id FROM resolution_unit_summary_versions WHERE workspace_id=?1 AND lang='rust' AND generation=?2 AND unit_key=?3 AND valid_from<=?4 AND (valid_until IS NULL OR ?4<valid_until)",
                params![snapshot.workspace_id.as_str(), snapshot.generation.0, unit.as_slice(), snapshot.revision],
                |r| r.get(0),
            ).unwrap();
            for row in AnalyzerStore::rust_summary_package_rows_for_unit(
                inventory.connection(),
                &snapshot,
                &unit,
            )
            .unwrap()
            {
                let ordinal: u32 = inventory.connection().query_row(
                    "SELECT member_ordinal FROM resolution_unit_summary_members WHERE summary_id=?1 AND rel_path=?2",
                    params![summary_id, row.rel_path], |r| r.get(0),
                ).unwrap();
                expected_packages
                    .entry(row.package_components.join("."))
                    .or_default()
                    .push((unit, ordinal));
                expected_files.entry(row.rel_path).or_default().push(unit);
            }
            for row in AnalyzerStore::rust_summary_cargo_route_rows_for_unit(
                inventory.connection(),
                &snapshot,
                &unit,
            )
            .unwrap()
            {
                if let Some(root) = row.root_rel_path.as_ref()
                    && matches!(row.target_kind.as_str(), "lib" | "bin")
                {
                    expected_names
                        .entry(row.crate_name.clone())
                        .or_default()
                        .push((unit, row.target_kind.clone(), root.clone()));
                }
                if let (Some(name), Some(child), Some(kind), Some(root)) = (
                    row.dependency_extern_name.as_ref(),
                    row.dependency_unit_key,
                    row.dependency_target_kind.as_ref(),
                    row.dependency_root_rel_path.as_ref(),
                ) && row.dependency_boundary.as_deref() == Some("workspace")
                    && matches!(kind.as_str(), "lib" | "bin")
                {
                    expected_names.entry(name.clone()).or_default().push((
                        child,
                        kind.clone(),
                        root.clone(),
                    ));
                }
                if let (Some(target), Some(kind)) = (row.dependency_unit_key, row.dependency_kind)
                    && row.dependency_boundary.as_deref() == Some("workspace")
                {
                    expected_deps.entry(target).or_default().push((unit, kind));
                }
            }
        }
        assert!(
            reachable_units > 0,
            "fixture has no published target reachability answer"
        );
        for (path, mut expected) in expected_files {
            expected.sort();
            expected.dedup();
            assert_eq!(
                rust_file_units(inventory.connection(), &snapshot, &path).unwrap(),
                expected
            );
            assert!(matches!(
                host.demand::<RustFileUnits>(analyzer.analyzer(), &inventory, &path),
                Demanded::Available { .. }
            ));
        }
        for (target, mut expected) in expected_deps {
            expected.sort();
            assert_eq!(
                rust_unit_dependents(inventory.connection(), &snapshot, &target).unwrap(),
                expected
            );
            assert!(matches!(
                host.demand::<RustUnitDependents>(analyzer.analyzer(), &inventory, &target),
                Demanded::Available { .. }
            ));
        }
        expected_names.entry("missing".to_string()).or_default();
        for (name, mut expected) in expected_names {
            expected.sort_by(|a, b| (&a.2, &a.0, &a.1).cmp(&(&b.2, &b.0, &b.1)));
            expected.dedup_by(|a, b| a.2 == b.2);
            assert_eq!(
                rust_crate_name_units(inventory.connection(), &snapshot, &name).unwrap(),
                expected
            );
            assert!(matches!(
                host.demand::<RustCrateNameUnits>(analyzer.analyzer(), &inventory, &name),
                Demanded::Available { .. }
            ));
        }
        expected_packages.entry("missing".to_string()).or_default();
        for (package, mut expected) in expected_packages {
            expected.sort();
            assert_eq!(
                rust_package_units(inventory.connection(), &snapshot, &package).unwrap(),
                expected
            );
            assert!(matches!(
                host.demand::<RustPackageUnits>(analyzer.analyzer(), &inventory, &package),
                Demanded::Available { .. }
            ));
        }
        // #11173: crate-name selection now searches the summary context.
        {
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
                .unwrap();
            conn.execute("DELETE FROM selected_workspace_revisions", [])
                .unwrap();
            conn.execute(
                "INSERT INTO selected_workspace_revisions SELECT workspace_id, lang, generation, revision FROM workspace_heads WHERE lang='rust'",
                [],
            ).unwrap();
            for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
                state.install(&conn);
                let plans = brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::explain_rust_route_questions(
                &conn, &snapshot, &[0;32], "app/src/lib.rs", "dep", "a",
            ).unwrap();
                let plan = &plans
                    .iter()
                    .find(|(name, _)| name == "crate_name_units")
                    .unwrap()
                    .1;
                eprintln!("{state:?} crate-name plan: {plan:?}");
                assert!(plan.iter().any(|p| p.contains("rust_resolution_unit_summary_contexts_name_kind (crate_name=? AND target_kind=?)")), "{state:?}: {plan:?}");
                assert!(
                    !plan.iter().any(|p| p.contains("MATERIALIZE live")
                        || p.starts_with("SCAN t")
                        || p.starts_with("SCAN v")),
                    "{state:?}: {plan:?}"
                );
                let sql = brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_crate_name_units_sql();
                let mut stmt = conn.prepare(&sql).unwrap();
                let rows = stmt.query_map(params![brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION, "dep"], |_| Ok(())).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                let scans = stmt.get_status(rusqlite::StatementStatus::FullscanStep);
                eprintln!(
                    "{state:?} crate-name rows={} fullscan_steps={scans}",
                    rows.len()
                );
                assert!(!rows.is_empty());
                assert!(scans < 12, "{state:?}: fullscan_steps={scans}");
                let wrong = sql.replace(
                    "rust_resolution_unit_summary_contexts_name_kind",
                    "rust_resolution_unit_summary_contexts_live",
                );
                let mut wrong_stmt = conn.prepare(&wrong).unwrap();
                wrong_stmt.query_map(params![brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION, "dep"], |_| Ok(())).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                let wrong_scans = wrong_stmt.get_status(rusqlite::StatementStatus::FullscanStep);
                eprintln!("{state:?} wrong-index fullscan_steps={wrong_scans}");
                assert!(
                    wrong_scans >= 12,
                    "{state:?}: wrong-index fullscan_steps={wrong_scans}"
                );
                for (kind, index) in [
                    ("dependents", "resolution_unit_summary_dependencies_unit"),
                    ("file_units", "resolution_unit_summary_members_path"),
                    (
                        "crate_name_units",
                        "rust_resolution_unit_summary_contexts_name_kind",
                    ),
                    (
                        "crate_name_units",
                        "resolution_unit_summary_dependency_names_name",
                    ),
                    (
                        "package_units",
                        "rust_resolution_unit_summary_file_naming_package",
                    ),
                ] {
                    let plan = &plans.iter().find(|(name, _)| name == kind).unwrap().1;
                    assert!(
                        plan.iter()
                            .any(|detail| detail.contains("SEARCH") && detail.contains(index)),
                        "{state:?} {kind}: {plan:?}"
                    );
                }
            }
        }

        // A source-only mod edit moves the input identity while the unit's
        // exported summary stays equal. The old fragment must be recomputed.
        let main_unit = rust_file_units(inventory.connection(), &snapshot, "dep/src/lib.rs")
            .unwrap()
            .into_iter()
            .find(|key| {
                AnalyzerStore::rust_summary_cargo_route_rows_for_unit(
                    inventory.connection(),
                    &snapshot,
                    key,
                )
                .unwrap()
                .iter()
                .any(|row| row.target_kind == "lib")
            })
            .unwrap();
        let digest = |d| match d {
            Demanded::Available { value, .. } => *value,
            Demanded::Unavailable(cause) => panic!("control input unavailable: {cause:?}"),
        };
        let summary_before =
            digest(host.demand::<UnitSummaryKind>(analyzer.analyzer(), &inventory, &main_unit));
        let inputs_before =
            digest(host.demand::<RustUnitInputs>(analyzer.analyzer(), &inventory, &main_unit));
        let recomputed_before = host.counters(RustUnitRoutes::ID).recomputed;
        let before_route = host.demand::<RustUnitRoutes>(
            analyzer.analyzer(),
            &inventory,
            &SelectedRustUnit::minted_by_test_fixture(main_unit, true),
        );
        assert!(matches!(before_route, Demanded::Available { .. }));
        let source = std::fs::read_to_string(project.root().join("dep/src/lib.rs")).unwrap();
        std::fs::write(project.root().join("dep/src/lib.rs"), format!("\n{source}")).unwrap();
        let changed = project.workspace_analyzer(AnalyzerConfig::default());
        let changed_store = changed.store().unwrap();
        let (workspace, generation, revision) = changed_store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        let changed_snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let changed_snapshots = std::iter::once(("rust".into(), changed_snapshot.clone()))
            .collect::<WorkspaceSnapshots>();
        let changed_inventory = match changed_store
            .open_selected_resolution_mount_inventory(
                &changed_snapshot.workspace_id,
                &changed_snapshots,
                &[SelectedResolutionLanguage::new(
                    "rust".to_string(),
                    Language::Rust,
                )],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(i) => i,
            _ => panic!("changed selection unavailable"),
        };
        assert!(
            rust_file_units(
                changed_inventory.connection(),
                &changed_snapshot,
                "dep/src/lib.rs"
            )
            .unwrap()
            .contains(&main_unit)
        );
        let summary_after = digest(host.demand::<UnitSummaryKind>(
            changed.analyzer(),
            &changed_inventory,
            &main_unit,
        ));
        let inputs_after = digest(host.demand::<RustUnitInputs>(
            changed.analyzer(),
            &changed_inventory,
            &main_unit,
        ));
        assert_eq!(summary_before, summary_after);
        assert_ne!(inputs_before, inputs_after);
        assert!(matches!(
            host.demand::<RustUnitRoutes>(
                changed.analyzer(),
                &changed_inventory,
                &SelectedRustUnit::minted_by_test_fixture(main_unit, true)
            ),
            Demanded::Available { .. }
        ));
        assert!(host.counters(RustUnitRoutes::ID).recomputed > recomputed_before);

        // A manifest comment changes its content OID while keeping the crate
        // topology. The input token moves, and the equal route answer cuts off
        // any parent that depends on this fragment's output identity.
        let topology = |connection: &rusqlite::Connection| -> Vec<u8> {
            connection.query_row(
                "SELECT t.topology_digest FROM rust_resolution_unit_summary_versions rv JOIN resolution_unit_summary_versions v ON v.workspace_id=rv.workspace_id AND v.lang=rv.lang AND v.generation=rv.generation AND v.unit_key=rv.unit_key AND v.valid_from=rv.valid_from JOIN rust_crate_topologies t ON t.topology_id=rv.topology_id WHERE rv.unit_key=?1 AND v.valid_until IS NULL",
                params![main_unit.as_slice()], |r| r.get(0),
            ).unwrap()
        };
        let topology_before = topology(changed_inventory.connection());
        let route_identity_before = match host.demand::<RustUnitRoutes>(
            changed.analyzer(),
            &changed_inventory,
            &SelectedRustUnit::minted_by_test_fixture(main_unit, true),
        ) {
            Demanded::Available { identity, .. } => identity,
            Demanded::Unavailable(cause) => {
                panic!("route before manifest edit unavailable: {cause:?}")
            }
        };
        let manifest = std::fs::read_to_string(project.root().join("dep/Cargo.toml")).unwrap();
        std::fs::write(
            project.root().join("dep/Cargo.toml"),
            format!("{manifest}\n# unchanged topology\n"),
        )
        .unwrap();
        let manifest_changed = project.workspace_analyzer(AnalyzerConfig::default());
        let manifest_store = manifest_changed.store().unwrap();
        let (workspace, generation, revision) = manifest_store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        let manifest_snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let manifest_snapshots = std::iter::once(("rust".into(), manifest_snapshot.clone()))
            .collect::<WorkspaceSnapshots>();
        let manifest_inventory = match manifest_store
            .open_selected_resolution_mount_inventory(
                &manifest_snapshot.workspace_id,
                &manifest_snapshots,
                &[SelectedResolutionLanguage::new(
                    "rust".to_string(),
                    Language::Rust,
                )],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(i) => i,
            _ => panic!("manifest selection unavailable"),
        };
        assert_eq!(topology_before, topology(manifest_inventory.connection()));
        let summary_manifest = digest(host.demand::<UnitSummaryKind>(
            manifest_changed.analyzer(),
            &manifest_inventory,
            &main_unit,
        ));
        let inputs_manifest = digest(host.demand::<RustUnitInputs>(
            manifest_changed.analyzer(),
            &manifest_inventory,
            &main_unit,
        ));
        assert_eq!(summary_after, summary_manifest);
        assert_ne!(inputs_after, inputs_manifest);
        let recomputed_manifest_before = host.counters(RustUnitRoutes::ID).recomputed;
        let route_identity_manifest = match host.demand::<RustUnitRoutes>(
            manifest_changed.analyzer(),
            &manifest_inventory,
            &SelectedRustUnit::minted_by_test_fixture(main_unit, true),
        ) {
            Demanded::Available { identity, .. } => identity,
            Demanded::Unavailable(cause) => {
                panic!("route after manifest edit unavailable: {cause:?}")
            }
        };
        assert_eq!(route_identity_before, route_identity_manifest);
        assert!(host.counters(RustUnitRoutes::ID).recomputed > recomputed_manifest_before);
    }

    #[test]
    fn broad_route_controls_survive_edits_and_ignore_old_topologies() {
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::{
            rust_broad_file_units, rust_crate_name_units,
        };
        use brokk_bifrost_core::CancellationToken;
        use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::{
            RustBroadFileUnits, RustCrateNameUnits, RustFileUnits, RustPackageUnits,
            RustSelectedUnitsKnown, RustTargetReachability, RustUnitDependents, RustUnitInputs,
            RustUnitRoutes, SelectedRustUnit,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{Demanded, DerivationKind};

        let project = fixture();
        let budget = RetentionBudget::new(1_000_000);
        let host = AnalyzerDerivations::new(&budget);
        let observe =
            |analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
             path: &str| {
                let store = analyzer.store().unwrap();
                let (workspace, generation, revision) = store.read_conn().unwrap().query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            ).unwrap();
                let snapshot = WorkspaceSnapshotId {
                    workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
                    lang: "rust".into(),
                    generation:
                        brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                            generation,
                        ),
                    revision,
                };
                let snapshots = std::iter::once(("rust".into(), snapshot.clone()))
                    .collect::<WorkspaceSnapshots>();
                let SelectedResolutionMountInventoryOutcome::Ready(inventory) = store
                    .open_selected_resolution_mount_inventory(
                        &snapshot.workspace_id,
                        &snapshots,
                        &[SelectedResolutionLanguage::new(
                            "rust".to_string(),
                            Language::Rust,
                        )],
                        &[],
                        &CancellationToken::default(),
                    )
                    .unwrap()
                else {
                    panic!("selection unavailable")
                };
                let unit =
                    rust_crate_name_units(inventory.connection(), &snapshot, "dep").unwrap()[0].0;
                let broad = rust_broad_file_units(inventory.connection(), &snapshot, path).unwrap();
                let demanded = host.demand::<RustBroadFileUnits>(
                    analyzer.analyzer(),
                    &inventory,
                    &path.to_string(),
                );
                let (value, complete) = match demanded {
                    Demanded::Available {
                        value, complete, ..
                    } => (value, complete),
                    Demanded::Unavailable(cause) => panic!("broad lookup unavailable: {cause:?}"),
                };
                assert_eq!(
                    value.iter().map(|unit| *unit.key()).collect::<Vec<_>>(),
                    broad
                );
                let stored_complete: bool = inventory.connection().query_row(
                "SELECT coalesce(min(t.broad_complete), 1) FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.workspace_id=?1 AND v.lang='rust' AND v.generation=?2 AND v.valid_from<=?3 AND (v.valid_until IS NULL OR ?3<v.valid_until)",
                params![snapshot.workspace_id.as_str(), snapshot.generation.0, snapshot.revision],
                |r| r.get(0),
            ).unwrap();
                let check = |answer: Option<bool>| assert_eq!(answer, Some(stored_complete));
                check(Some(complete));
                macro_rules! check_complete {
                    ($answer:expr) => {
                        check(match $answer {
                            Demanded::Available { complete, .. } => Some(complete),
                            Demanded::Unavailable(cause) => {
                                panic!("{} unavailable: {cause:?}", stringify!($answer))
                            }
                        })
                    };
                }
                check_complete!(host.demand::<RustSelectedUnitsKnown>(
                    analyzer.analyzer(),
                    &inventory,
                    &0
                ));
                check_complete!(host.demand::<RustFileUnits>(
                    analyzer.analyzer(),
                    &inventory,
                    &path.to_string()
                ));
                check_complete!(host.demand::<RustPackageUnits>(
                    analyzer.analyzer(),
                    &inventory,
                    &String::new()
                ));
                check_complete!(host.demand::<RustCrateNameUnits>(
                    analyzer.analyzer(),
                    &inventory,
                    &"dep".to_string()
                ));
                check_complete!(host.demand::<RustUnitDependents>(
                    analyzer.analyzer(),
                    &inventory,
                    &unit
                ));
                check_complete!(host.demand::<RustTargetReachability>(
                    analyzer.analyzer(),
                    &inventory,
                    &SelectedRustUnit::minted_by_test_fixture(unit, true)
                ));
                let input =
                    match host.demand::<RustUnitInputs>(analyzer.analyzer(), &inventory, &unit) {
                        Demanded::Available {
                            identity, complete, ..
                        } => {
                            check(Some(complete));
                            identity
                        }
                        Demanded::Unavailable(cause) => panic!("input unavailable: {cause:?}"),
                    };
                let routes = match host.demand::<RustUnitRoutes>(
                    analyzer.analyzer(),
                    &inventory,
                    &SelectedRustUnit::minted_by_test_fixture(unit, true),
                ) {
                    Demanded::Available {
                        identity,
                        value,
                        complete,
                        ..
                    } => {
                        check(Some(complete));
                        let _ = value;
                        identity
                    }
                    Demanded::Unavailable(cause) => panic!("routes unavailable: {cause:?}"),
                };
                (unit, broad, input, routes)
            };
        let original = project.workspace_analyzer(AnalyzerConfig::default());
        let (unit, broad, input, _) = observe(&original, "dep/src/off.rs");
        assert_eq!(broad, vec![unit]);
        let brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::Multi(multi) =
            &original
        else {
            panic!("Rust analyzer missing")
        };
        let rust = multi.delegates().get(&Language::Rust).unwrap().analyzer();
        let rust = (rust as &dyn std::any::Any)
            .downcast_ref::<brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer>()
            .unwrap();
        let off = ProjectFile::new(project.root().to_path_buf(), "dep/src/off.rs");
        assert_eq!(
            brokk_bifrost_rust::graph_support::RustSource::file_routes(rust, &off, None)
                .unwrap()
                .target_roots(&off),
            vec![ProjectFile::new(
                project.root().to_path_buf(),
                "dep/src/lib.rs"
            )],
        );
        std::fs::write(
            project.root().join("dep/src/off.rs"),
            "pub fn disabled() { let changed = 1; let _ = changed; }",
        )
        .unwrap();
        let edited = project.workspace_analyzer(AnalyzerConfig::default());
        let (_, _, next_input, _) = observe(&edited, "dep/src/off.rs");
        assert_ne!(input, next_input);
        assert!(host.counters(RustUnitRoutes::ID).recomputed >= 2);
        std::fs::write(project.root().join("dep/src/lib.rs"), "pub struct X(pub u8); #[cfg(feature = \"on\")] pub mod on; #[cfg(feature = \"off\")] pub mod replacement;").unwrap();
        std::fs::write(
            project.root().join("dep/src/replacement.rs"),
            "pub fn replacement() {}",
        )
        .unwrap();
        let replaced = project.workspace_analyzer(AnalyzerConfig::default());
        // Reconciliation prunes unbound topologies, so retain a historical
        // placement explicitly. It has dep's key and the current producer
        // epoch, but no selected crate version binds its topology id.
        replaced.store().unwrap().conn.execute(move |conn| {
            conn.execute(
                "INSERT INTO rust_crate_topologies(topology_digest,crate_key,producer_epoch,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,export_surface_digest,publication_state,broad_complete)
                 SELECT randomblob(32),crate_key,producer_epoch,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,export_surface_digest,publication_state,broad_complete
                 FROM rust_crate_topologies WHERE topology_id=(SELECT topology_id FROM rust_crate_versions WHERE crate_key=?1 AND valid_until IS NULL)",
                [unit.as_slice()],
            )?;
            let historical = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO rust_crate_inactive_placements(topology_id,module_path,rel_path,placement,mount_blob_id,mount_start_byte,scope_ordinal,blob_id,activation)
                 SELECT ?1,module_path,'dep/src/off.rs',placement,mount_blob_id,mount_start_byte,scope_ordinal,blob_id,activation
                 FROM rust_crate_inactive_placements WHERE topology_id=(SELECT topology_id FROM rust_crate_versions WHERE crate_key=?2 AND valid_until IS NULL) AND rel_path='dep/src/replacement.rs'",
                params![historical, unit.as_slice()],
            )?;
            Ok::<(), rusqlite::Error>(())
        }).unwrap();
        let historical_rows: i64 = replaced.store().unwrap().read_conn().unwrap().query_row(
            "SELECT count(*) FROM rust_crate_inactive_placements p JOIN rust_crate_topologies t USING(topology_id) WHERE p.rel_path='dep/src/off.rs' AND t.crate_key=?1",
            [unit.as_slice()], |r| r.get(0),
        ).unwrap();
        assert!(historical_rows > 0, "historical placement was not retained");
        let (_, old, _, _) = observe(&replaced, "dep/src/off.rs");
        let (_, new, _, _) = observe(&replaced, "dep/src/replacement.rs");
        assert!(
            old.is_empty(),
            "historical topology leaked into broad lookup"
        );
        assert_eq!(new, vec![unit]);
        let store = replaced.store().unwrap();
        let oid: String = store.read_conn().unwrap().query_row(
            "SELECT blob_oid FROM workspace_file_versions WHERE lang='rust' AND rel_path='dep/src/replacement.rs' AND valid_until IS NULL LIMIT 1",
            [], |row| row.get(0),
        ).unwrap();
        store.drop_rust_route_witness_for_blob_for_test("rust", Oid::from_str(&oid).unwrap());
        let (workspace, generation, revision) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let snapshots =
            std::iter::once(("rust".into(), snapshot.clone())).collect::<WorkspaceSnapshots>();
        let SelectedResolutionMountInventoryOutcome::Ready(inventory) = store
            .open_selected_resolution_mount_inventory(
                &snapshot.workspace_id,
                &snapshots,
                &[SelectedResolutionLanguage::new(
                    "rust".to_string(),
                    Language::Rust,
                )],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        else {
            panic!("selection unavailable")
        };
        let missing_host = AnalyzerDerivations::new(&budget);
        assert!(
            matches!(
                missing_host.demand::<RustUnitRoutes>(
                    replaced.analyzer(),
                    &inventory,
                    &SelectedRustUnit::minted_by_test_fixture(unit, true)
                ),
                Demanded::Available {
                    complete: false,
                    ..
                }
            ),
            "broad-only file without facts must leave the route fragment incomplete"
        );
    }

    #[test]
    fn rust_route_change_controls() {
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_file_units;
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::CancellationToken;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::{
            RustCrateNameUnits, RustTargetReachability, RustUnitDependents, RustUnitInputs,
            RustUnitNaming, RustUnitRoutes, SelectedRustUnit,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            Demanded, DerivationKind, OutputIdentity,
        };

        // Each row gets an independent store, while its two observations use
        // the same derivation host to test verification across revisions.
        #[derive(Clone, Copy, Debug)]
        enum Edit {
            Member,
            AddDependency,
            MoveRoot,
            CloseRebind,
            NewCrate,
            Nested,
            SharedRename,
            SharedVersion,
        }
        fn observe(
            analyzer: &WorkspaceAnalyzer,
            host: &AnalyzerDerivations,
            root_path: &str,
            expected_files: &[&str],
        ) -> (
            [u8; 32],
            OutputIdentity,
            OutputIdentity,
            OutputIdentity,
            OutputIdentity,
            OutputIdentity,
            Vec<String>,
            OutputIdentity,
            u64,
        ) {
            let store = analyzer.store().unwrap();
            let (workspace, generation, revision) = store.read_conn().unwrap().query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            ).unwrap();
            let snapshot = WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    generation,
                ),
                revision,
            };
            let snapshots =
                std::iter::once(("rust".into(), snapshot.clone())).collect::<WorkspaceSnapshots>();
            let inventory = match store
                .open_selected_resolution_mount_inventory(
                    &snapshot.workspace_id,
                    &snapshots,
                    &[SelectedResolutionLanguage::new(
                        "rust".to_string(),
                        Language::Rust,
                    )],
                    &[],
                    &CancellationToken::default(),
                )
                .unwrap()
            {
                SelectedResolutionMountInventoryOutcome::Ready(i) => i,
                _ => panic!("selection unavailable"),
            };
            let unit = rust_file_units(inventory.connection(), &snapshot, root_path).unwrap()[0];
            fn identity<T>(d: Demanded<T>) -> OutputIdentity {
                match d {
                    Demanded::Available { identity, .. } => identity,
                    Demanded::Unavailable(cause) => panic!("control unavailable: {cause:?}"),
                }
            }
            let inputs =
                identity(host.demand::<RustUnitInputs>(analyzer.analyzer(), &inventory, &unit));
            let dependents =
                identity(host.demand::<RustUnitDependents>(analyzer.analyzer(), &inventory, &unit));
            let routes = identity(host.demand::<RustUnitRoutes>(
                analyzer.analyzer(),
                &inventory,
                &SelectedRustUnit::minted_by_test_fixture(unit, true),
            ));
            let route_naming_count = host.counters(RustUnitNaming::ID).recomputed;
            let naming =
                identity(host.demand::<RustUnitNaming>(analyzer.analyzer(), &inventory, &unit));
            let name = identity(host.demand::<RustCrateNameUnits>(
                analyzer.analyzer(),
                &inventory,
                &"c".to_string(),
            ));
            let reach = host.demand::<RustTargetReachability>(
                analyzer.analyzer(),
                &inventory,
                &SelectedRustUnit::minted_by_test_fixture(unit, true),
            );
            let (reach_identity, answer) = match reach {
                Demanded::Available {
                    identity, value, ..
                } => (
                    identity,
                    value
                        .roots
                        .iter()
                        .find(|entry| entry.root == root_path)
                        .unwrap_or_else(|| panic!("the unit lists {root_path} as a root"))
                        .files
                        .clone(),
                ),
                Demanded::Unavailable(cause) => panic!("reachability unavailable: {cause:?}"),
            };
            let expected = expected_files
                .iter()
                .map(|path| (*path).to_owned())
                .collect::<Vec<_>>();
            assert_eq!(answer, expected, "fixture reachability for {root_path}");
            (
                unit,
                inputs,
                dependents,
                routes,
                reach_identity,
                name,
                answer,
                naming,
                route_naming_count,
            )
        }
        for edit in [
            Edit::Member,
            Edit::AddDependency,
            Edit::MoveRoot,
            Edit::CloseRebind,
            Edit::NewCrate,
            Edit::Nested,
            Edit::SharedRename,
            Edit::SharedVersion,
        ] {
            let dependency = matches!(edit, Edit::MoveRoot);
            let b_manifest = format!(
                "[package]\nname='b'\nversion='0.1.0'\nedition='2021'\n{}",
                if dependency {
                    "[dependencies]\na={path='../a'}\n"
                } else {
                    ""
                }
            );
            let project = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[workspace]\nmembers=['a','b']\nresolver='2'\n",
                )
                .file(
                    "a/Cargo.toml",
                    "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file("b/Cargo.toml", b_manifest)
                .file(
                    "a/src/lib.rs",
                    if matches!(edit, Edit::SharedRename | Edit::SharedVersion) {
                        "#[path = \"../../shared/x.rs\"] pub mod shared; pub fn a() {}"
                    } else {
                        "pub fn a() {}"
                    },
                )
                .file("shared/x.rs", "pub fn shared() {}")
                .file(
                    "shared/Cargo.toml",
                    "[package]\nname='shared'\nversion='0.1.0'\n[lib]\npath='x.rs'\n",
                )
                .file("b/src/lib.rs", "pub fn b() {}")
                .build();
            let budget = RetentionBudget::new(1_000_000);
            let host = AnalyzerDerivations::new(&budget);
            let initial = project.certified_workspace_analyzer(AnalyzerConfig::default());
            let before_files: &[&str] = if matches!(edit, Edit::SharedRename | Edit::SharedVersion)
            {
                &["a/src/lib.rs", "shared/x.rs"]
            } else if matches!(edit, Edit::MoveRoot) {
                &["a/src/lib.rs", "b/src/lib.rs"]
            } else {
                &["a/src/lib.rs"]
            };
            let before = observe(&initial, &host, "a/src/lib.rs", before_files);
            let counts = (
                host.counters(RustUnitRoutes::ID).recomputed,
                host.counters(RustTargetReachability::ID).recomputed,
            );
            let naming_count = host.counters(RustUnitNaming::ID).recomputed;
            match edit {
                Edit::Nested => {
                    std::fs::write(
                        project.root().join("a/src/Cargo.toml"),
                        "[package]\nname='nested'\nversion='0.1.0'\n",
                    )
                    .unwrap();
                }
                Edit::SharedRename | Edit::SharedVersion => {
                    let extra = if matches!(edit, Edit::SharedRename) {
                        "name='renamed'\n"
                    } else {
                        ""
                    };
                    std::fs::write(
                        project.root().join("shared/Cargo.toml"),
                        format!(
                            "[package]\nname='shared'\nversion='0.2.0'\n[lib]\npath='x.rs'\n{extra}"
                        ),
                    )
                    .unwrap();
                }
                Edit::Member => {
                    std::fs::write(
                        project.root().join("a/src/lib.rs"),
                        "pub mod extra; pub fn a() {}",
                    )
                    .unwrap();
                    std::fs::write(project.root().join("a/src/extra.rs"), "pub fn extra() {}")
                        .unwrap();
                }
                Edit::AddDependency => {
                    std::fs::write(
                        project.root().join("b/Cargo.toml"),
                        format!(
                            "[package]\nname='b'\nversion='0.1.0'\nedition='2021'\n{}",
                            if matches!(edit, Edit::AddDependency) {
                                "[dependencies]\na={path='../a'}\n"
                            } else {
                                ""
                            }
                        ),
                    )
                    .unwrap();
                }
                Edit::MoveRoot => {
                    std::fs::write(project.root().join("a/Cargo.toml"),
                        "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='src/moved.rs'\n").unwrap();
                    std::fs::rename(
                        project.root().join("a/src/lib.rs"),
                        project.root().join("a/src/moved.rs"),
                    )
                    .unwrap();
                }
                Edit::CloseRebind => {
                    std::fs::write(
                        project.root().join("Cargo.toml"),
                        "[workspace]\nmembers=['b']\nexclude=['a']\nresolver='2'\n",
                    )
                    .unwrap();
                    std::fs::remove_dir_all(project.root().join("a")).unwrap();
                    let closed = project.certified_workspace_analyzer(AnalyzerConfig::default());
                    let closed_store = closed.store().unwrap();
                    let count: i64 = closed_store.read_conn().unwrap().query_row(
                        "SELECT count(*) FROM resolution_unit_summary_versions WHERE unit_key=?1 AND valid_until IS NULL",
                        [before.0.as_slice()], |r| r.get(0)).unwrap();
                    assert_eq!(count, 0, "closed unit still selected");
                    std::fs::write(
                        project.root().join("Cargo.toml"),
                        "[workspace]\nmembers=['a','b']\nresolver='2'\n",
                    )
                    .unwrap();
                    std::fs::create_dir_all(project.root().join("a/src")).unwrap();
                    std::fs::write(
                        project.root().join("a/Cargo.toml"),
                        "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n",
                    )
                    .unwrap();
                    std::fs::write(project.root().join("a/src/lib.rs"), "pub fn a() {}").unwrap();
                }
                Edit::NewCrate => {
                    std::fs::create_dir_all(project.root().join("c/src")).unwrap();
                    std::fs::write(
                        project.root().join("c/Cargo.toml"),
                        "[package]\nname='c'\nversion='0.1.0'\nedition='2021'\n",
                    )
                    .unwrap();
                    std::fs::write(project.root().join("c/src/lib.rs"), "pub fn c() {}").unwrap();
                    std::fs::write(
                        project.root().join("Cargo.toml"),
                        "[workspace]\nmembers=['a','b','c']\nresolver='2'\n",
                    )
                    .unwrap();
                }
            }
            let changed = project.certified_workspace_analyzer(AnalyzerConfig::default());
            let root_path = if matches!(edit, Edit::MoveRoot) {
                "a/src/moved.rs"
            } else {
                "a/src/lib.rs"
            };
            let after_files: &[&str] = match edit {
                Edit::Member => &["a/src/extra.rs", "a/src/lib.rs"],
                Edit::MoveRoot => &["a/src/moved.rs", "b/src/lib.rs"],
                Edit::AddDependency => &["a/src/lib.rs", "b/src/lib.rs"],
                _ => before_files,
            };
            let after = observe(&changed, &host, root_path, after_files);
            let new_counts = (
                host.counters(RustUnitRoutes::ID).recomputed,
                host.counters(RustTargetReachability::ID).recomputed,
            );
            match edit {
                Edit::Nested | Edit::SharedRename => {
                    assert!(
                        after.8 > naming_count,
                        "{edit:?}: routes must demand the naming child before reachability"
                    );
                    assert!(
                        new_counts.0 > counts.0,
                        "{edit:?}: naming change must recompute routes"
                    );
                }
                Edit::SharedVersion => {
                    assert!(
                        host.counters(RustUnitNaming::ID).recomputed > naming_count,
                        "version edit must recompute naming"
                    );
                    assert_eq!(
                        before.7, after.7,
                        "version-only edit changed naming identity"
                    );
                    assert_eq!(before.6, after.6, "version-only edit changed route answers");
                }
                Edit::Member | Edit::MoveRoot => {
                    assert_ne!(before.1, after.1, "{edit:?} input");
                    assert_ne!(before.3, after.3, "{edit:?} route");
                    assert!(
                        new_counts.0 > counts.0 && new_counts.1 > counts.1,
                        "{edit:?}: {counts:?} -> {new_counts:?}"
                    );
                }
                Edit::AddDependency => {
                    assert_ne!(before.1, after.1, "{edit:?} target input");
                    assert_ne!(before.2, after.2, "{edit:?} dependents");
                    assert!(
                        new_counts.0 > counts.0,
                        "{edit:?}: {counts:?} -> {new_counts:?}"
                    );
                    assert!(
                        new_counts.1 > counts.1,
                        "{edit:?}: {counts:?} -> {new_counts:?}"
                    );
                }
                Edit::CloseRebind => {
                    assert_eq!(before.1, after.1, "{edit:?} input");
                    assert_eq!(before.3, after.3, "{edit:?} route");
                    assert_eq!(before.6, after.6, "{edit:?} answer");
                    assert_eq!(new_counts, counts, "{edit:?} should reuse equal parents");
                }
                Edit::NewCrate => {
                    assert_ne!(before.1, after.1, "{edit:?} input");
                    assert_ne!(before.5, after.5, "{edit:?} crate name");
                    assert_eq!(before.6, after.6, "{edit:?} answer");
                    assert!(
                        new_counts.0 > counts.0,
                        "{edit:?}: {counts:?} -> {new_counts:?}"
                    );
                    assert_eq!(
                        new_counts.1, counts.1,
                        "{edit:?} equal route cuts off reachability"
                    );
                }
            }
            if matches!(edit, Edit::AddDependency) {
                std::fs::write(
                    project.root().join("b/Cargo.toml"),
                    "[package]\nname='b'\nversion='0.1.0'\nedition='2021'\n",
                )
                .unwrap();
                let removed = project.certified_workspace_analyzer(AnalyzerConfig::default());
                let back = observe(&removed, &host, "a/src/lib.rs", before_files);
                assert_eq!(before.1, back.1, "removed dependency restores input");
                assert_eq!(before.2, back.2, "removed dependency restores dependents");
                assert_eq!(
                    before.6, back.6,
                    "removed dependency restores oracle answer"
                );
                assert!(host.counters(RustTargetReachability::ID).recomputed > new_counts.1);
            }
        }
    }

    #[test]
    fn rust_route_incomplete_summary_propagates_to_fragment_and_reachability() {
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_file_units;
        use brokk_bifrost_core::CancellationToken;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::{
            RustTargetReachability, RustUnitInputs, RustUnitRoutes, SelectedRustUnit,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;

        let project = cycle_fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let (workspace, generation, revision) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let snapshots =
            std::iter::once(("rust".into(), snapshot.clone())).collect::<WorkspaceSnapshots>();
        let inventory = match store
            .open_selected_resolution_mount_inventory(
                &snapshot.workspace_id,
                &snapshots,
                &[SelectedResolutionLanguage::new(
                    "rust".to_string(),
                    Language::Rust,
                )],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(i) => i,
            _ => panic!("selection unavailable"),
        };
        let unit =
            rust_file_units(inventory.connection(), &snapshot, "config/src/lib.rs").unwrap()[0];
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        assert!(matches!(
            host.demand::<RustUnitInputs>(analyzer.analyzer(), &inventory, &unit),
            Demanded::Available {
                complete: false,
                ..
            }
        ));
        assert!(matches!(
            host.demand::<RustUnitRoutes>(
                analyzer.analyzer(),
                &inventory,
                &SelectedRustUnit::minted_by_test_fixture(unit, true)
            ),
            Demanded::Available {
                complete: false,
                ..
            }
        ));
        assert!(matches!(
            host.demand::<RustTargetReachability>(
                analyzer.analyzer(),
                &inventory,
                &SelectedRustUnit::minted_by_test_fixture(unit, true)
            ),
            Demanded::Available {
                complete: false,
                ..
            }
        ));
        assert!(
            matches!(
                host.demand::<RustUnitRoutes>(
                    analyzer.analyzer(),
                    &inventory,
                    &SelectedRustUnit::minted_by_test_fixture(unit, true)
                ),
                Demanded::Available {
                    complete: false,
                    ..
                }
            ),
            "a retained fragment must preserve incomplete membership"
        );
        // Remove the root inventory witness for one published member. The
        // published-facts view then omits that member while its crate summary
        // still exists, matching a missing module-facts read.
        let oid: String = store.read_conn().unwrap().query_row(
            "SELECT blob_oid FROM workspace_file_versions WHERE lang='rust' AND rel_path='config/src/lib.rs' AND valid_until IS NULL LIMIT 1",
            [], |row| row.get(0),
        ).unwrap();
        store.drop_rust_route_witness_for_blob_for_test("rust", Oid::from_str(&oid).unwrap());
        let missing_host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        assert!(matches!(
            missing_host.demand::<RustUnitRoutes>(
                analyzer.analyzer(),
                &inventory,
                &SelectedRustUnit::minted_by_test_fixture(unit, true)
            ),
            Demanded::Available {
                complete: false,
                ..
            }
        ));
    }

    /// Whether each route question answers on a fresh host at the store's
    /// current Rust head: the selection check, a file, a package, a crate
    /// name, and the dependents of the unit that holds `file`.
    fn route_question_availability(
        analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        file: &str,
        crate_name: &str,
        host: &brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations,
    ) -> Vec<(&'static str, Option<bool>)> {
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_file_units;
        use brokk_bifrost_core::CancellationToken;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::{
            RustCrateNameUnits, RustFileUnits, RustPackageUnits, RustSelectedUnitsKnown,
            RustUnitDependents,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;

        let store = analyzer.store().unwrap();
        let (workspace, generation, revision) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let snapshots =
            std::iter::once(("rust".into(), snapshot.clone())).collect::<WorkspaceSnapshots>();
        let SelectedResolutionMountInventoryOutcome::Ready(inventory) = store
            .open_selected_resolution_mount_inventory(
                &snapshot.workspace_id,
                &snapshots,
                &[SelectedResolutionLanguage::new(
                    "rust".to_string(),
                    Language::Rust,
                )],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        else {
            panic!("selection unavailable")
        };
        let unit = rust_file_units(inventory.connection(), &snapshot, file).unwrap()[0];
        fn available<T>(answer: Demanded<T>) -> Option<bool> {
            match answer {
                Demanded::Available { complete, .. } => Some(complete),
                Demanded::Unavailable(_) => None,
            }
        }
        let a = analyzer.analyzer();
        let scope = AnalyzerQueryScope::capturing_read_incompleteness(a);
        let answers = vec![
            (
                "known",
                available(host.demand::<RustSelectedUnitsKnown>(a, &inventory, &0)),
            ),
            (
                "file",
                available(host.demand::<RustFileUnits>(a, &inventory, &file.to_string())),
            ),
            (
                "package",
                available(host.demand::<RustPackageUnits>(a, &inventory, &String::new())),
            ),
            (
                "name",
                available(host.demand::<RustCrateNameUnits>(
                    a,
                    &inventory,
                    &crate_name.to_string(),
                )),
            ),
            (
                "dependents",
                available(host.demand::<RustUnitDependents>(a, &inventory, &unit)),
            ),
        ];
        if answers.iter().all(|(_, answer)| *answer == Some(true)) {
            assert!(
                !scope
                    .captured_read_incompleteness()
                    .iter()
                    .any(|reason| matches!(
                        reason,
                        brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(
                            _
                        )
                    )),
                "complete route questions recorded membership incompleteness"
            );
        }
        if answers.iter().all(|(_, answer)| *answer == Some(false)) {
            assert!(
                scope
                    .captured_read_incompleteness()
                    .iter()
                    .any(|reason| matches!(
                        reason,
                        brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(
                            _
                        )
                    ))
            );
            for _ in 0..2 {
                let hit_scope = AnalyzerQueryScope::capturing_read_incompleteness(a);
                assert!(matches!(
                    host.demand::<RustFileUnits>(a, &inventory, &"src/absent.rs".to_string()),
                    Demanded::Available { value, complete: false, .. } if value.is_empty()
                ));
                assert!(
                    hit_scope
                        .captured_read_incompleteness()
                        .iter()
                        .any(|reason| matches!(
                    reason,
                    brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(_)
                ))
                );
            }
            let SelectedResolutionMountInventoryOutcome::Ready(rebound) = store
                .open_selected_resolution_mount_inventory(
                    &snapshot.workspace_id,
                    &snapshots,
                    &[SelectedResolutionLanguage::new(
                        "rust".to_string(),
                        Language::Rust,
                    )],
                    &[],
                    &CancellationToken::default(),
                )
                .unwrap()
            else {
                panic!("rebound selection unavailable")
            };
            let rebound_scope = AnalyzerQueryScope::capturing_read_incompleteness(a);
            assert!(matches!(
                host.demand::<RustFileUnits>(a, &rebound, &"src/absent.rs".to_string()),
                Demanded::Available { value, complete: false, .. } if value.is_empty()
            ));
            assert!(
                rebound_scope
                    .captured_read_incompleteness()
                    .iter()
                    .any(|reason| matches!(
                        reason,
                        brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(
                            _
                        )
                    ))
            );
        }
        answers
    }

    fn route_question_availability_fresh(
        analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        file: &str,
        crate_name: &str,
    ) -> Vec<(&'static str, Option<bool>)> {
        let host = brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations::new(
            &brokk_bifrost_core::retention_budget::RetentionBudget::new(1_000_000),
        );
        route_question_availability(analyzer, file, crate_name, &host)
    }

    fn all_route_questions(answer: Option<bool>) -> Vec<(&'static str, Option<bool>)> {
        ["known", "file", "package", "name", "dependents"]
            .map(|name| (name, answer))
            .to_vec()
    }

    fn selected_broad_complete(
        analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
    ) -> bool {
        analyzer
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT coalesce(min(t.broad_complete), 1) FROM rust_crate_versions v
             JOIN rust_crate_topologies t USING(topology_id)
             WHERE v.lang='rust' AND v.valid_until IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn route_questions_are_unavailable_while_a_selected_crate_has_no_summary() {
        let project = fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            route_question_availability_fresh(&analyzer, "dep/src/lib.rs", "dep"),
            all_route_questions(Some(selected_broad_complete(&analyzer)))
        );
        // A selected crate whose summary is not published: its membership
        // is unknown, so no question about the selection's units is exhaustive.
        analyzer
            .store()
            .unwrap()
            .conn
            .execute(|conn| {
                conn.execute(
                    "INSERT INTO rust_crate_versions(workspace_id,lang,generation,crate_key,valid_from,valid_until,manifest_file_version_id,topology_id)
                     SELECT workspace_id,lang,generation,?1,valid_from,valid_until,NULL,topology_id
                     FROM rust_crate_versions WHERE lang='rust' AND valid_until IS NULL LIMIT 1",
                    [[9_u8; 32].as_slice()],
                )
            })
            .unwrap();
        assert_eq!(
            route_question_availability_fresh(&analyzer, "dep/src/lib.rs", "dep"),
            all_route_questions(None)
        );
    }

    #[test]
    fn route_questions_are_unavailable_while_a_selected_crate_inventory_is_incomplete() {
        let crate_with = |lib: &str| {
            InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"open_inventory\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                )
                .file("src/lib.rs", lib)
                .build()
        };
        let complete = crate_with("pub fn library() {}\n");
        let complete_analyzer = complete.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            route_question_availability_fresh(&complete_analyzer, "src/lib.rs", "open_inventory"),
            all_route_questions(Some(selected_broad_complete(&complete_analyzer)))
        );
        // A module declaration with no file leaves the crate's inventory
        // incomplete while its summary still publishes: the files it would
        // hold are unknown.
        let open = crate_with("pub fn library() {}\nmod missing;\n");
        let analyzer = open.workspace_analyzer(AnalyzerConfig::default());
        let inventory_complete: bool = analyzer
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT t.inventory_complete FROM rust_crate_versions v
                 JOIN rust_crate_topologies t USING(topology_id)
                 WHERE v.lang='rust' AND v.valid_until IS NULL AND t.crate_name='open_inventory'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!inventory_complete);
        let host = brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations::new(
            &brokk_bifrost_core::retention_budget::RetentionBudget::new(1_000_000),
        );
        assert_eq!(
            route_question_availability(&analyzer, "src/lib.rs", "open_inventory", &host),
            all_route_questions(Some(selected_broad_complete(&analyzer)))
        );
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::RustSelectedUnitsKnown;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind;
        let first = host.counters(RustSelectedUnitsKnown::ID);
        assert!(first.recomputed > 0);
        std::fs::write(open.root().join("src/missing.rs"), "pub fn present() {}\n").unwrap();
        let completed = open.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            route_question_availability(&completed, "src/lib.rs", "open_inventory", &host),
            all_route_questions(Some(selected_broad_complete(&completed)))
        );
        let second = host.counters(RustSelectedUnitsKnown::ID);
        assert!(
            second.recomputed > first.recomputed
                || second.verified_unchanged > first.verified_unchanged
        );
    }

    #[test]
    fn keyed_route_negative_alias_and_duplicate_blob_controls() {
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::{
            rust_crate_name_units, rust_file_units,
        };
        use brokk_bifrost_core::CancellationToken;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::{
            RustCrateNameUnits, RustFileUnits, RustUnitDependents,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::Demanded;
        let run = |aliases: usize, new_file: bool, parent_present: bool, rebound: bool| {
            let mut builder = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    if parent_present {
                        "[workspace]\nmembers=[\"a\",\"b\",\"p\",\"q\"]\nresolver=\"2\"\n"
                    } else {
                        "[workspace]\nmembers=[\"a\",\"b\",\"q\"]\nresolver=\"2\"\n"
                    },
                )
                .file(
                    "a/Cargo.toml",
                    "[package]\nname=\"a\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file(
                    "b/Cargo.toml",
                    "[package]\nname=\"b\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file(
                    "q/Cargo.toml",
                    format!(
                        "[package]\nname=\"q\"\nversion=\"0.1.0\"\nedition=\"2021\"\n{}",
                        if aliases >= 2 {
                            "[dependencies]\nborrowed={package=\"b\",path=\"../b\"}\n"
                        } else {
                            ""
                        }
                    ),
                )
                .file(
                    "a/src/lib.rs",
                    format!(
                        "pub mod shared; {}",
                        if new_file {
                            "pub mod new;"
                        } else if rebound {
                            "pub fn unrelated() {}"
                        } else {
                            ""
                        }
                    ),
                )
                .file("b/src/lib.rs", "pub mod shared;")
                .file("a/src/shared.rs", "pub fn same() {}")
                .file("b/src/shared.rs", "pub fn same() {}")
                .file("q/src/lib.rs", "pub fn q() {}");
            if parent_present {
                builder = builder
                    .file(
                        "p/Cargo.toml",
                        format!(
                            "[package]\nname=\"p\"\nversion=\"0.1.0\"\nedition=\"2021\"\n{}",
                            if aliases >= 1 {
                                "[dependencies]\nborrowed={package=\"a\",path=\"../a\"}\n"
                            } else {
                                ""
                            }
                        ),
                    )
                    .file("p/src/lib.rs", "pub fn p() {}");
            }
            if new_file {
                builder = builder.file("a/src/new.rs", "pub fn new() {}");
            }
            let project = builder.build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let (w,g,r)=store.read_conn().unwrap().query_row("SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",[],|row|Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?))).unwrap();
            let snapshot = WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(w),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    g,
                ),
                revision: r,
            };
            let snapshots = std::iter::once(("rust".to_string(), snapshot.clone()))
                .collect::<WorkspaceSnapshots>();
            let inventory = match store
                .open_selected_resolution_mount_inventory(
                    &snapshot.workspace_id,
                    &snapshots,
                    &[SelectedResolutionLanguage::new(
                        "rust".to_string(),
                        Language::Rust,
                    )],
                    &[],
                    &CancellationToken::default(),
                )
                .unwrap()
            {
                SelectedResolutionMountInventoryOutcome::Ready(i) => i,
                _ => panic!("selection unavailable"),
            };
            let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
            let name =
                rust_crate_name_units(inventory.connection(), &snapshot, "borrowed").unwrap();
            let a = rust_file_units(inventory.connection(), &snapshot, "a/src/shared.rs").unwrap();
            let b = rust_file_units(inventory.connection(), &snapshot, "b/src/shared.rs").unwrap();
            assert_eq!(a.len(), 1);
            assert_eq!(b.len(), 1);
            assert_ne!(a, b, "identical blobs at distinct paths must not fan out");
            fn answer<T: Clone>(d: Demanded<T>) -> T {
                match d {
                    Demanded::Available { value, .. } => (*value).clone(),
                    Demanded::Unavailable(_) => panic!("route demand unavailable"),
                }
            }
            let name_digest = answer(host.demand::<RustCrateNameUnits>(
                analyzer.analyzer(),
                &inventory,
                &"borrowed".to_string(),
            ));
            let file_digest = answer(host.demand::<RustFileUnits>(
                analyzer.analyzer(),
                &inventory,
                &"a/src/new.rs".to_string(),
            ));
            let dep_digest =
                answer(host.demand::<RustUnitDependents>(analyzer.analyzer(), &inventory, &a[0]));
            (name.len(), name_digest, file_digest, dep_digest)
        };
        let absent = run(0, false, true, false);
        let one = run(1, false, true, false);
        let two = run(2, true, true, false);
        let closed = run(1, false, false, false);
        let rebound = run(1, false, true, true);
        assert_eq!((absent.0, one.0, two.0), (0, 1, 2));
        assert_ne!(absent.1, one.1);
        assert_ne!(one.1, two.1);
        assert_eq!(absent.2, one.2);
        assert_ne!(one.2, two.2);
        assert_ne!(absent.3, one.3);
        assert_eq!(closed.0, 0);
        assert_eq!(closed.1, absent.1);
        assert_eq!(closed.3, absent.3);
        assert_eq!(rebound.1, one.1);
        assert_eq!(rebound.2, one.2);
        assert_eq!(rebound.3, one.3);
    }

    /// Vector's crate graph in small: `config` and `macros` form a cycle
    /// through a dev-dependency, because lib targets carry their
    /// dev-dependencies, and `relay` and `app` depend on the cycle from
    /// outside it. `app` reaches `config` only through `relay`'s re-export.
    fn cycle_fixture() -> BuiltInlineTestProject {
        InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"config\", \"macros\", \"relay\", \"app\"]\nresolver = \"2\"\n")
            .file("config/Cargo.toml", "[package]\nname = \"config\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nmacros = { path = \"../macros\" }\n")
            .file("macros/Cargo.toml", "[package]\nname = \"macros\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dev-dependencies]\nconfig = { path = \"../config\" }\n")
            .file("relay/Cargo.toml", "[package]\nname = \"relay\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nconfig = { path = \"../config\" }\n")
            .file("app/Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrelay = { path = \"../relay\" }\n")
            .file("config/src/lib.rs", "pub mod inner { pub struct Name; } pub fn body() {}")
            .file("macros/src/lib.rs", "pub struct Derive;")
            .file("relay/src/lib.rs", "pub use config::inner;")
            .file("app/src/lib.rs", "pub use relay::inner; pub mod sub;")
            .file("app/src/sub.rs", "use relay::inner::Name as Viar; pub fn make(_: Viar) {}")
            .build()
    }

    /// When no crate is ready, only the cycle is forced. Its members are
    /// derived without each other and are the only incomplete inventories;
    /// a crate that depends on the cycle waits for it, so `relay` and `app`
    /// see their dependencies and `app`'s routes continue through `relay`
    /// into `config`.
    #[test]
    #[hardwon("#10774+#10830: warm stores retained target-layout manifest gaps")]
    fn warm_manifest_gap_upgrade_rederives_detached_crate() {
        if run_derivation_version_child() {
            return;
        }
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n")
            .file("src/lib.rs", "pub fn lib() {}")
            .file("src/bin/tool/main.rs", "fn main() {}")
            .file("scratch.rs", "pub fn loose() {}")
            .build();
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let cache =
            std::sync::Arc::new(WorkspaceFileListingCache::new(project.root().to_path_buf()));
        let filesystem = std::sync::Arc::new(
            FilesystemProject::with_cached_listing(project.root(), cache).unwrap(),
        );
        let build =
            || WorkspaceAnalyzer::build_persisted(filesystem.clone(), AnalyzerConfig::default());
        let old = RUST_CRATE_DERIVATION_VERSION
            .split_once("-10774-manifests-only-cargo-toml")
            .unwrap()
            .0;
        set_derivation_version(Some(old));
        let first = build();
        set_derivation_version(None);
        let first = first.unwrap();
        // Reproduce the pre-fix detached topology, including its retained gap.
        // Its digest and reconciliation marker were built under the old version.
        first
            .store()
            .unwrap()
            .conn
            .execute_fixture(|conn| {
                conn.execute_batch(
            r#"UPDATE rust_crate_topologies SET broad_complete=0 WHERE target_kind='detached';
             INSERT INTO rust_crate_gaps
             SELECT topology_id, 'unsupported_manifest', '',
                    jsonb('{"detail":"src/bin/tool/main.rs: invalid Cargo manifest"}')
             FROM rust_crate_topologies WHERE target_kind='detached';"#
        )
            })
            .unwrap();
        let gap_count = |analyzer: &WorkspaceAnalyzer| -> i64 {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM rust_crate_versions v
                 JOIN rust_crate_gaps g USING(topology_id)
                 WHERE v.valid_until IS NULL AND g.gap_kind='unsupported_manifest'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(gap_count(&first), 1);
        let snapshots = |analyzer: &WorkspaceAnalyzer| -> WorkspaceSnapshots {
            let snapshot = analyzer.store().unwrap().read_conn().unwrap().query_row(
                "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                [], |row| Ok(WorkspaceSnapshotId {
                    workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(row.get(0)?),
                    lang: "rust".into(),
                    generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(row.get(1)?),
                    revision: row.get(2)?,
                })
            ).unwrap();
            [("rust".into(), snapshot)].into_iter().collect()
        };
        let old_snapshots = snapshots(&first);
        first
            .store()
            .unwrap()
            .conn
            .execute_fixture(|conn| {
                conn.execute_batch(
                    "DELETE FROM rust_resolution_unit_summary_versions;
             DELETE FROM resolution_unit_summary_versions WHERE lang='rust';
             DELETE FROM resolution_unit_summaries WHERE lang='rust';",
                )
            })
            .unwrap();
        set_derivation_version(Some(old));
        let summaries = first
            .store()
            .unwrap()
            .reconcile_rust_unit_summaries(&old_snapshots["rust"]);
        set_derivation_version(None);
        assert!(summaries.unwrap().failed.is_empty());
        let binding_complete = |analyzer: &WorkspaceAnalyzer| {
            let rows = analyzer
                .store()
                .unwrap()
                .rust_summary_binding_completeness_rows(
                    &snapshots(analyzer),
                    &["scratch.rs".to_owned()],
                )
                .unwrap();
            assert!(
                !rows.is_empty(),
                "the detached file has a stored import completeness row"
            );
            rows.iter().all(|row| row.complete)
        };
        assert!(
            !binding_complete(&first),
            "the old manifest gap makes imports incomplete"
        );
        drop(first);
        let upgraded = build().unwrap();
        assert!(
            binding_complete(&upgraded),
            "the warm upgrade replaces stale import completeness"
        );
        assert_eq!(
            gap_count(&upgraded),
            0,
            "the warm upgrade withdraws the old manifest gap"
        );
        let complete: bool = upgraded
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT t.broad_complete FROM rust_crate_versions v
             JOIN rust_crate_topologies t USING(topology_id)
             WHERE v.valid_until IS NULL AND t.target_kind='detached'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            complete,
            "the detached context inventory is complete after reopening"
        );
    }

    #[test]
    #[hardwon("#10774+#10830: a target-layout .rs root was parsed as a Cargo manifest")]
    fn only_cargo_toml_inputs_are_read_as_manifests() {
        // Since #10774 a package's `src/bin/<name>/main.rs` is a recorded
        // configuration input, beside Cargo.lock and the toolchain file. Bat
        // has one: its four detached files all carried an unsupported_manifest
        // gap naming src/bin/bat/main.rs, which made the selected unit set
        // incomplete and every inverse answer partial.
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "Cargo.lock",
                "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
            )
            .file("rust-toolchain.toml", "[toolchain]\nchannel = \"stable\"\n")
            .file("src/lib.rs", "pub fn lib() {}")
            .file("src/bin/tool/main.rs", "mod app;\nfn main() {}")
            .file("src/bin/tool/app.rs", "pub fn run() {}")
            .file("scratch.rs", "pub fn loose() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let strings = |sql: &str| -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(
            strings(
                "SELECT t.crate_name || ' ' || t.target_kind
                 FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id)
                 WHERE v.valid_until IS NULL ORDER BY 1"
            ),
            ["app lib", "scratch.rs detached", "tool bin"],
            "the bin's layout root is a target, not a manifest"
        );
        assert_eq!(
            strings(
                "SELECT t.crate_name || ' -> ' || g.detail
                 FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id)
                 JOIN rust_crate_gaps g USING(topology_id)
                 WHERE v.valid_until IS NULL AND g.gap_kind = 'unsupported_manifest' ORDER BY 1"
            ),
            Vec::<String>::new(),
            "no crate inherits a manifest error from a configuration input that is not Cargo.toml"
        );
        let listing: bool = conn
            .query_row(
                "SELECT complete FROM rust_source_listing_certificates
                 ORDER BY revision DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let detached: bool = conn
            .query_row(
                "SELECT t.broad_complete
                 FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id)
                 WHERE v.valid_until IS NULL AND t.target_kind = 'detached'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            detached, listing,
            "the detached crate is as complete as the listing makes it"
        );
    }

    #[test]
    #[hardwon(
        "aaac3511d800: a dependency cycle forced every pending crate into one wave, so downstream crates were derived without their dependencies"
    )]
    fn a_dependency_cycle_forces_only_its_own_crates() {
        let project = cycle_fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let strings = |sql: &str| -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(
            strings(
                "SELECT t.crate_name || ' ' || t.target_kind || ' ' || t.inventory_complete
                 FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id)
                 WHERE v.valid_until IS NULL ORDER BY 1"
            ),
            ["app lib 1", "config lib 0", "macros lib 0", "relay lib 1"],
            "only the two cycle members are incomplete inventories"
        );
        assert_eq!(
            strings(
                "SELECT t.crate_name || ' -> ' || g.subject
                 FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id)
                 JOIN rust_crate_gaps g USING(topology_id)
                 WHERE v.valid_until IS NULL AND g.gap_kind = 'unsupported_manifest' ORDER BY 1"
            ),
            ["config -> macros", "macros -> config"],
            "the cycle members are derived without each other, and nothing else misses a dependency"
        );
        let config: String = conn
            .query_row(
                "SELECT hex(crate_key) FROM rust_crate_topologies WHERE crate_name = 'config'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            strings(
                "SELECT i.bound_name || ' ' || i.namespace || ' ' || hex(i.target_crate_key) || ' ' || i.target_module_path || ' ' || i.target_name
                 FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id)
                 JOIN rust_crate_imports i USING(topology_id)
                 WHERE v.valid_until IS NULL AND t.crate_name = 'app' AND i.module_path = 'crate::sub' ORDER BY 1"
            ),
            [
                format!("Viar type {config} crate::inner Name"),
                format!("Viar value {config} crate::inner Name"),
            ],
            "app's route continues through relay's re-export into config"
        );
        assert_eq!(
            strings(
                "SELECT e.module_path || ' ' || e.name || ' ' || e.origin
                 FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id)
                 JOIN rust_crate_exports e USING(topology_id)
                 WHERE v.valid_until IS NULL AND t.crate_name = 'app' AND e.name = 'inner' ORDER BY 1"
            ),
            ["crate inner reexport"],
            "app re-exports the module relay re-exported from config"
        );
    }

    #[test]
    #[hardwon("#4503: chained Rust re-exports replayed every export fixpoint pass")]
    fn rust_crate_reexport_chain_reports_fixpoint_scaling() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

        use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::begin_legacy_export_compare;

        use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::begin_route_pass_metric_capture;

        use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::take_export_fixpoint_pass_metrics;

        use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::take_legacy_export_compare_metrics;

        use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::take_route_pass_metrics;

        for size in [64usize, 128, 256, 512, 1024] {
            let crate_name = format!("reexport_scale_{size}");
            let mut source = String::with_capacity(size * 64);
            source.push_str("pub mod m0 { pub struct Item; }\n");
            for index in 1..=size {
                use std::fmt::Write as _;
                writeln!(
                    source,
                    "pub mod m{index} {{ pub use crate::m{}::Item; }}",
                    index - 1
                )
                .unwrap();
            }
            let project = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    format!(
                        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    ),
                )
                .file("src/lib.rs", source)
                .build();

            begin_route_pass_metric_capture();
            begin_legacy_export_compare(&crate_name);
            let analyzer = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .expect("the generated Cargo crate builds in the analyzer");
            let export_metrics = take_export_fixpoint_pass_metrics()
                .into_iter()
                .filter(|(name, _)| name == &crate_name)
                .map(|(_, metric)| metric)
                .collect::<Vec<_>>();
            let route_metrics = take_route_pass_metrics()
                .into_iter()
                .filter(|(name, _)| name == &crate_name)
                .map(|(_, metric)| metric)
                .collect::<Vec<_>>();
            let legacy_compare = take_legacy_export_compare_metrics(&crate_name)
                .into_iter()
                .find(|metrics| metrics.crate_name == crate_name)
                .expect("the legacy SQL run compares the generated crate exports");
            assert_eq!(legacy_compare.legacy_passes, size + 1);
            eprintln!(
                "legacy-export-parity n={size} passes={} rows={} digest={}",
                legacy_compare.legacy_passes,
                legacy_compare.export_rows,
                legacy_compare.exports_digest
            );
            for metric in &route_metrics {
                eprintln!(
                    "route-pass n={size} pass={} import_rows_read={} reexport_steps_read={} glob_steps_read={} routes_written={} reexport_steps_written={} reexport_closure_deleted={} reexport_closure_written={} glob_steps_written={} glob_closure_deleted={} glob_closure_written={} vm_steps={}",
                    metric.pass,
                    metric.source_import_rows_read,
                    metric.reexport_step_rows_read,
                    metric.glob_step_rows_read,
                    metric.route_rows_written,
                    metric.reexport_step_rows_written,
                    metric.reexport_closure_rows_deleted,
                    metric.reexport_closure_rows_written,
                    metric.glob_step_rows_written,
                    metric.glob_closure_rows_deleted,
                    metric.glob_closure_rows_written,
                    metric.sqlite_vm_steps,
                );
            }
            for metric in &export_metrics {
                eprintln!(
                    "export-pass n={size} pass={} delta_rows_read={} source_rows={} rows_written={} vm_steps={} elapsed_us={}",
                    metric.pass,
                    metric.delta_rows_read,
                    metric.source_rows,
                    metric.rows_written,
                    metric.sqlite_vm_steps,
                    metric.elapsed_micros,
                );
            }

            let store = analyzer.store().expect("the fixture has an analyzer store");
            let conn = store.read_conn().expect("read the derived crate rows");
            let topology_id: i64 = conn
                .query_row(
                    "SELECT topologies.topology_id
                     FROM rust_crate_versions AS versions
                     JOIN rust_crate_topologies AS topologies USING(topology_id)
                     WHERE topologies.crate_name=?1 AND versions.valid_until IS NULL",
                    [&crate_name],
                    |row| row.get(0),
                )
                .expect("find the live generated crate topology");
            let reexport_route_rows: i64 = conn
                .query_row(
                    "SELECT count(*) FROM rust_crate_reexport_routes
                     WHERE topology_id=?1 AND visibility='public'",
                    [topology_id],
                    |row| row.get(0),
                )
                .expect("count public re-export routes");
            let reexport_export_rows: i64 = conn
                .query_row(
                    "SELECT count(*) FROM rust_crate_exports
                     WHERE topology_id=?1 AND origin='reexport'",
                    [topology_id],
                    |row| row.get(0),
                )
                .expect("count public re-export rows");
            assert_eq!(reexport_route_rows, size as i64);
            assert_eq!(reexport_export_rows, (size * 2) as i64);

            let export_delta_rows_read: usize = export_metrics
                .iter()
                .map(|metric| metric.delta_rows_read)
                .sum();
            let export_source_rows = export_metrics
                .first()
                .map(|metric| metric.source_rows)
                .expect("the export fixpoint records every pass");
            let export_rows_written: usize = export_metrics
                .iter()
                .map(|metric| metric.rows_written)
                .sum();
            let export_vm_steps: u64 = export_metrics
                .iter()
                .map(|metric| metric.sqlite_vm_steps)
                .sum();
            let route_source_rows_read: usize = route_metrics
                .iter()
                .map(|metric| metric.source_import_rows_read)
                .sum();
            let route_reexport_step_rows_read: usize = route_metrics
                .iter()
                .map(|metric| metric.reexport_step_rows_read)
                .sum();
            let route_glob_step_rows_read: usize = route_metrics
                .iter()
                .map(|metric| metric.glob_step_rows_read)
                .sum();
            let route_rows_written: usize = route_metrics
                .iter()
                .map(|metric| metric.route_rows_written)
                .sum();
            let route_reexport_rows_written: usize = route_metrics
                .iter()
                .map(|metric| {
                    metric.reexport_step_rows_written + metric.reexport_closure_rows_written
                        - metric.reexport_closure_rows_deleted
                })
                .sum();
            let route_glob_rows_written: usize = route_metrics
                .iter()
                .map(|metric| {
                    metric.glob_step_rows_written + metric.glob_closure_rows_written
                        - metric.glob_closure_rows_deleted
                })
                .sum();
            let route_vm_steps: u64 = route_metrics
                .iter()
                .map(|metric| metric.sqlite_vm_steps)
                .sum();
            let route_passes = route_metrics
                .iter()
                .map(|metric| metric.pass)
                .max()
                .unwrap_or_default();
            let export_passes = export_metrics
                .iter()
                .map(|metric| metric.pass + 1)
                .max()
                .unwrap_or_default();
            let export_elapsed_micros: u64 = export_metrics
                .iter()
                .map(|metric| metric.elapsed_micros)
                .sum();
            let derive_elapsed_micros = export_metrics
                .first()
                .map(|metric| metric.derive_elapsed_micros)
                .expect("test metrics capture the crate derivation");

            eprintln!(
                "route-scale n={size} route_passes={route_passes} route_source_rows_read={route_source_rows_read} route_reexport_step_rows_read={route_reexport_step_rows_read} route_glob_step_rows_read={route_glob_step_rows_read} route_rows_written={route_rows_written} route_reexport_rows_written={route_reexport_rows_written} route_glob_rows_written={route_glob_rows_written} route_vm_steps={route_vm_steps} export_passes={export_passes} export_source_rows={export_source_rows} export_delta_rows_read={export_delta_rows_read} export_rows_written={export_rows_written} export_vm_steps={export_vm_steps} export_elapsed_ms={:.3} derive_ms={:.3}",
                export_elapsed_micros as f64 / 1000.0,
                derive_elapsed_micros as f64 / 1000.0,
            );
            if size == 1024 {
                assert!(
                    export_delta_rows_read <= size * 8,
                    "delta propagation reads must stay linear: n={size} rows={export_delta_rows_read}"
                );
                assert!(
                    export_vm_steps <= size as u64 * 2_000,
                    "delta propagation VM steps must stay bounded: n={size} steps={export_vm_steps}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#3827: a Cargo bench root without a parsed blob must publish an incomplete topology"
    )]
    fn cargo_benchmark_without_a_root_blob_publishes_incomplete_topology() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"bench_root_gap\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [[bench]]\nname = \"cold_root\"\nharness = false\n",
            )
            .file("src/lib.rs", "pub fn library() {}\n")
            .file("benches/cold_root.rs", "fn main() {}\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let snapshot = {
            let conn = store.read_conn().unwrap();
            let row = conn
                .query_row(
                    "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap();
            WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(row.0),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    row.1,
                ),
                revision: row.2,
            }
        };
        let workspace_id = snapshot.workspace_id.as_str().to_owned();
        let generation = snapshot.generation.0;
        let updated = store
            .conn
            .execute(move |conn| -> Result<_> {
                Ok(conn.execute(
                    "UPDATE workspace_file_versions SET blob_oid=?1
                     WHERE workspace_id=?2 AND lang='rust' AND generation=?3
                       AND rel_path='benches/cold_root.rs' AND valid_until IS NULL",
                    params![
                        "ffffffffffffffffffffffffffffffffffffffff",
                        workspace_id,
                        generation
                    ],
                )?)
            })
            .unwrap();
        assert_eq!(
            updated, 1,
            "the benchmark root must be in the workspace snapshot"
        );

        store.reconcile_rust_crates(&snapshot).unwrap();

        let conn = store.read_conn().unwrap();
        let (topology_id, inventory_complete, prelude) = conn
            .query_row(
                "SELECT topologies.topology_id, topologies.inventory_complete, topologies.prelude
                 FROM rust_crate_versions AS versions
                 JOIN rust_crate_topologies AS topologies USING(topology_id)
                 WHERE versions.workspace_id=?1 AND versions.lang='rust'
                   AND versions.generation=?2 AND versions.valid_until IS NULL
                   AND topologies.crate_name='cold_root' AND topologies.target_kind='bench'",
                params![snapshot.workspace_id.as_str(), snapshot.generation.0],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert!(!inventory_complete);
        assert_eq!(prelude, "none");

        let (kind, subject, detail) = conn
            .query_row(
                "SELECT gap_kind, subject, json(detail) FROM rust_crate_gaps
                 WHERE topology_id=?1 AND subject='crate'",
                [topology_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            (kind.as_str(), subject.as_str()),
            ("unplaced_module", "crate")
        );
        let detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(detail["path"], "benches/cold_root.rs");
        assert_eq!(detail["activation"], 1);
    }

    fn current_crate_digests(conn: &Connection) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        conn.prepare("SELECT t.crate_key,t.topology_digest,t.export_surface_digest FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL ORDER BY t.crate_key").unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    /// A scoped reconcile publishes what the from-scratch pass would.
    ///
    /// Gate 13: one changed file costs its own crates, not the workspace. The
    /// oracle is the from-scratch pass on the same cache right after the
    /// scoped one, which must find nothing left to change.
    ///
    /// Each edit goes through `update`, which is what production calls, so the
    /// store really holds the new blob; a reconcile run against an unchanged
    /// blob proves nothing. `app` depends on `dep`, so `app`'s digest folds
    /// `dep`'s export surface, and that surface is export names rather than
    /// signatures: only the third edit moves it and only that one may derive
    /// `app` again.
    #[test]
    fn a_scoped_reconcile_publishes_what_the_full_pass_would() {
        let fixture = fixture();
        let mut analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());

        let head = |store: &AnalyzerStore| {
            let row = store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap();
            WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(row.0),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    row.1,
                ),
                revision: row.2,
            }
        };
        let app_digest = |store: &AnalyzerStore| -> Vec<u8> {
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT t.topology_digest FROM rust_crate_versions v
                     JOIN rust_crate_topologies t USING(topology_id)
                     WHERE v.valid_until IS NULL AND t.crate_name='app' AND t.target_kind='lib'",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .unwrap()
        };

        let inactive: (i64, i64) = analyzer
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT count(*), topologies.broad_complete
                 FROM rust_crate_inactive_placements AS placements
                 JOIN rust_crate_versions AS versions USING(topology_id)
                 JOIN rust_crate_topologies AS topologies USING(topology_id)
                 WHERE versions.valid_until IS NULL AND topologies.crate_name='dep'
                   AND topologies.target_kind='lib' AND placements.rel_path='dep/src/off.rs'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            inactive.0 > 0,
            "the inactive selected file has a broad placement"
        );
        assert_eq!(inactive.1, 1, "the listed inactive file is broad complete");

        for (path, contents, reaches_dependents) in [
            // A body: no export name moves.
            (
                "dep/src/on.rs",
                "pub fn enabled() { let body = 1; let _ = body; }",
                false,
            ),
            // An inactive placement changes the broad digest, but no export.
            (
                "dep/src/off.rs",
                "pub fn disabled() { let body = 1; let _ = body; }",
                false,
            ),
            // A signature: still no export name moves. The crate rows record
            // what a crate exports, not how it is called.
            ("dep/src/on.rs", "pub fn enabled(_added: u8) {}", false),
            // A new public item: the export surface moves, so `app` is derived
            // again even though no file of `app` changed.
            (
                "dep/src/on.rs",
                "pub fn enabled(_added: u8) {} pub fn appeared() {}",
                true,
            ),
        ] {
            let before = app_digest(analyzer.store().unwrap().as_ref());
            let file = fixture.file(path);
            file.write(contents).unwrap();
            analyzer = analyzer.update(&BTreeSet::from([file]));
            let store = analyzer.store().unwrap();
            let dep_broad: bool = store.read_conn().unwrap().query_row(
                "SELECT t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.crate_name='dep' AND t.target_kind='lib'",
                [],
                |row| row.get(0),
            ).unwrap();
            assert!(
                dep_broad,
                "the edited dep retains its broad certificate: {path}"
            );
            assert_eq!(
                app_digest(store.as_ref()) != before,
                reaches_dependents,
                "{path}: a dependent is derived again exactly when its dependency's \
                 export surface moved"
            );
            let scoped = current_crate_digests(&store.read_conn().unwrap());
            store.reconcile_rust_crates(&head(store.as_ref())).unwrap();
            assert_eq!(
                current_crate_digests(&store.read_conn().unwrap()),
                scoped,
                "{path}: the from-scratch pass must find nothing the scoped pass missed"
            );
        }

        // The same oracle with a dependency cycle. A scoped pass seeds every
        // crate it does not derive from the stored rows, so a cycle member
        // reached alone would see its peer where the from-scratch pass, which
        // forces the cycle as one wave, does not. Reaching one member reaches
        // the whole cycle.
        let cycle = cycle_fixture();
        let mut cycle_analyzer = cycle.certified_workspace_analyzer(AnalyzerConfig::default());
        for (path, contents) in [
            // A body in a cycle member.
            (
                "config/src/lib.rs",
                "pub mod inner { pub struct Name; } pub fn body() { let body = 1; let _ = body; }",
            ),
            // A new public item in a cycle member: its dependents outside the
            // cycle and its peer inside it are derived again.
            (
                "config/src/lib.rs",
                "pub mod inner { pub struct Name; pub struct Added; } pub fn body() {}",
            ),
            // The other member's surface moves.
            (
                "macros/src/lib.rs",
                "pub struct Derive; pub struct Attribute;",
            ),
            // A crate outside the cycle.
            (
                "app/src/sub.rs",
                "use relay::inner::Name as Viar; pub fn make(_: Viar) { let body = 1; let _ = body; }",
            ),
        ] {
            let file = cycle.file(path);
            file.write(contents).unwrap();
            cycle_analyzer = cycle_analyzer.update(&BTreeSet::from([file]));
            let store = cycle_analyzer.store().unwrap();
            let scoped = current_crate_digests(&store.read_conn().unwrap());
            store.reconcile_rust_crates(&head(store.as_ref())).unwrap();
            assert_eq!(
                current_crate_digests(&store.read_conn().unwrap()),
                scoped,
                "{path}: with a cycle, the from-scratch pass must find nothing the scoped pass missed"
            );
        }

        // Broad placements must follow an inactive file across removal,
        // creation and rename, including the detached crate born on rename.
        let off = fixture.file("dep/src/off.rs");
        let renamed = fixture.file("dep/src/off_renamed.rs");
        let compare_cold = |label: &str,
                            analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
            let warm = current_crate_digests(&analyzer.store().unwrap().read_conn().unwrap());
            let cold = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            let cold = current_crate_digests(&cold.store().unwrap().read_conn().unwrap());
            assert_eq!(warm, cold, "{label}: incremental and fresh topologies differ");
        };
        std::fs::remove_file(off.abs_path()).unwrap();
        analyzer = analyzer.update(&BTreeSet::from([off.clone()]));
        compare_cold("inactive removal", &analyzer);
        off.write("pub fn disabled() { let created = 1; let _ = created; }")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([off.clone()]));
        compare_cold("inactive creation", &analyzer);
        std::fs::rename(off.abs_path(), renamed.abs_path()).unwrap();
        analyzer = analyzer.update(&BTreeSet::from([off.clone(), renamed.clone()]));
        compare_cold("inactive rename", &analyzer);
        std::fs::rename(renamed.abs_path(), off.abs_path()).unwrap();
        analyzer = analyzer.update(&BTreeSet::from([off.clone(), renamed]));
        compare_cold("inactive rename reversal", &analyzer);

        // The same oracle for a detached file. A scoped pass that removed the
        // reached crate from the set it carries forward would close its live
        // version row, and every summary reader would lose the file.
        let detached = fixture.file("detached.rs");
        detached
            .write("pub fn detached() { let body = 1; let _ = body; }")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([detached]));
        let store = analyzer.store().unwrap();
        let scoped = current_crate_digests(&store.read_conn().unwrap());
        store.reconcile_rust_crates(&head(store.as_ref())).unwrap();
        assert_eq!(
            current_crate_digests(&store.read_conn().unwrap()),
            scoped,
            "detached.rs: the from-scratch pass must find nothing the scoped pass missed"
        );

        // A manifest can move crate membership, so it is never scoped.
        // Ordinary new module paths now use the recorded probes (#10552).
        let store = analyzer.store().unwrap();
        let snapshot = head(store.as_ref());
        {
            let path = "dep/Cargo.toml";
            assert!(
                matches!(
                    store
                        .rust_crate_reconcile_scope(
                            &snapshot,
                            snapshot.revision,
                            &[path.to_owned()]
                        )
                        .unwrap(),
                    CrateReconcileScope::Everything
                ),
                "{path} must reconcile the whole workspace"
            );
        }
        assert!(
            matches!(
                store
                    .rust_crate_reconcile_scope(
                        &snapshot,
                        snapshot.revision,
                        &["dep/src/on.rs".to_owned()]
                    )
                    .unwrap(),
                CrateReconcileScope::Reached { .. }
            ),
            "the certified placed file permits scoped reconciliation"
        );
    }

    /// A fresh process after a body edit scopes reconciliation when broad
    /// membership has a positive completeness certificate.
    #[test]
    fn a_fresh_process_after_a_body_edit_preserves_unreached_crates() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        let project = fixture();
        let build = || {
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("the workspace builds")
        };
        // Each open crate version as (crate name and target kind, topology id).
        let open = |analyzer: &WorkspaceAnalyzer| -> Vec<(String, i64)> {
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            conn
                .prepare(
                    "SELECT topologies.crate_name || ' ' || topologies.target_kind, versions.topology_id
                     FROM rust_crate_versions AS versions
                     JOIN rust_crate_topologies AS topologies USING(topology_id)
                     WHERE versions.valid_until IS NULL ORDER BY 1",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<(String, i64)>>>()
                .unwrap()
        };
        let forget = |analyzer: &WorkspaceAnalyzer, name: &'static str| {
            analyzer
                .store()
                .unwrap()
                .conn
                .execute(move |conn| {
                    conn.execute(
                        "DELETE FROM rust_crate_versions WHERE valid_until IS NULL AND topology_id IN
                           (SELECT topology_id FROM rust_crate_topologies WHERE crate_name = ?1)",
                        [name],
                    )
                })
                .unwrap()
        };
        let moved = |before: &[(String, i64)], after: &[(String, i64)]| -> Vec<String> {
            before
                .iter()
                .filter(|entry| !after.contains(entry))
                .map(|(name, _)| name.clone())
                .collect()
        };

        let first = build();
        let before = open(&first);
        // Forget helper at the head the first process published. The
        // marker stays there, so the next process sees a stale marker.
        forget(&first, "helper");
        drop(first);

        let file = project.file("app/src/a.rs");
        file.write("use super::*; pub fn b() { let body = 2; } pub fn original() {}")
            .unwrap();
        let second = build();
        let edited = open(&second);
        assert!(
            !edited.iter().any(|(name, _)| name == "helper lib"),
            "the certified broad relation keeps the body edit scoped"
        );
        let untouched_before: Vec<(String, i64)> = before
            .iter()
            .filter(|(name, _)| !name.starts_with("helper "))
            .cloned()
            .collect();
        assert_eq!(
            moved(&untouched_before, &edited),
            vec!["app lib".to_owned()],
            "only the edited crate's topology moved"
        );
        // Forget helper at the head the second process published. The
        // marker stays at that head, so the next process sees a stale marker.
        forget(&second, "helper");
        drop(second);

        // The mirror case: a manifest can move crate membership, so the
        // whole workspace is walked and helper is restored.
        let manifest = project.file("helper/Cargo.toml");
        manifest
            .write("[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n# touched\n")
            .unwrap();
        let third = build();
        assert!(
            open(&third).iter().any(|(name, _)| name == "helper lib"),
            "a manifest edit reconciles every crate, which restores helper"
        );
    }

    /// A warm start skips the full reconcile exactly while the marker says the
    /// crate rows are current for the head revision and derivation version.
    ///
    /// The skip is observed by removing one open crate version behind the
    /// marker's back: a start that skips leaves it missing, and a start
    /// without the marker runs the full pass, which restores it. An
    /// incremental update advances the marker to the head it reconciled.
    #[test]
    fn a_warm_start_skips_the_full_reconcile_only_while_the_marker_is_current() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        let project = fixture();
        let build = || {
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("the workspace builds")
        };
        let read = |analyzer: &WorkspaceAnalyzer, sql: &str| -> Vec<(i64, String)> {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .prepare(sql)
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let marker = |analyzer: &WorkspaceAnalyzer| {
            read(
                analyzer,
                "SELECT revision, derivation_version FROM rust_crate_reconciliations",
            )
        };
        let current = |analyzer: &WorkspaceAnalyzer| {
            read(
                analyzer,
                "SELECT revision, '' FROM workspace_heads WHERE lang = 'rust'",
            )
            .into_iter()
            .map(|(revision, _)| (revision, RUST_CRATE_DERIVATION_VERSION.to_owned()))
            .collect::<Vec<_>>()
        };
        let open_versions = |analyzer: &WorkspaceAnalyzer| {
            read(
                analyzer,
                "SELECT count(*), '' FROM rust_crate_versions WHERE valid_until IS NULL",
            )[0]
            .0
        };
        let tamper = |analyzer: &WorkspaceAnalyzer, sql: &'static str| {
            analyzer
                .store()
                .unwrap()
                .conn
                .execute(move |conn| conn.execute(sql, []))
                .unwrap()
        };

        let first = build();
        assert_eq!(
            marker(&first),
            current(&first),
            "a full pass records the marker"
        );
        let open = open_versions(&first);
        assert_eq!(
            tamper(
                &first,
                "DELETE FROM rust_crate_versions WHERE valid_until IS NULL AND crate_key =
                   (SELECT min(crate_key) FROM rust_crate_versions WHERE valid_until IS NULL)"
            ),
            1
        );
        drop(first);

        let skipped = build();
        assert_eq!(
            open_versions(&skipped),
            open - 1,
            "a start with a current marker walks no crate"
        );
        assert_eq!(
            tamper(&skipped, "DELETE FROM rust_crate_reconciliations"),
            1
        );
        drop(skipped);

        let recovered = build();
        assert_eq!(
            open_versions(&recovered),
            open,
            "a start without the marker runs the full pass"
        );
        let recovered_marker = marker(&recovered);
        assert_eq!(recovered_marker, current(&recovered));

        let file = project.file("dep/src/on.rs");
        file.write("pub fn enabled() { let body = 1; let _ = body; }")
            .unwrap();
        let updated = recovered.update(&BTreeSet::from([file]));
        let after_update = marker(&updated);
        assert_eq!(
            after_update,
            current(&updated),
            "the scoped pass advances the marker"
        );
        assert_ne!(
            after_update, recovered_marker,
            "the update opened a revision"
        );
    }

    #[test]
    #[hardwon(
        "9888333a0d7f: external import boundaries must not be reported as missing local routes"
    )]
    fn crate_import_gaps_distinguish_external_boundaries_from_missing_local_routes() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = \"boundaries\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nanyhow = \"1\"\n")
            .file("src/lib.rs", "use std::path::PathBuf; use anyhow::Result; use anyhow as error_lib; use crate::missing::Local; #[cfg(any())] use absent::Inactive;")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let gaps = conn.prepare("SELECT gap_kind, subject FROM rust_crate_gaps WHERE subject IN ('crate::PathBuf','crate::Result','crate::Local','crate::Inactive','crate::error_lib') ORDER BY subject,gap_kind")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            gaps,
            vec![
                ("unresolved_import".into(), "crate::Local".into()),
                ("external_dependency".into(), "crate::PathBuf".into()),
                ("open_export_inventory".into(), "crate::PathBuf".into()),
                ("external_dependency".into(), "crate::Result".into()),
                ("open_export_inventory".into(), "crate::Result".into()),
                ("external_dependency".into(), "crate::error_lib".into()),
                ("open_export_inventory".into(), "crate::error_lib".into()),
            ]
        );
    }

    /// A `#[path]` module declared in an ordinary module file resolves against
    /// that file's own directory, the way Rust resolves it.
    ///
    /// The shared inline test harness is declared as
    /// `#[cfg(test)] #[path = "../../.../test-support/inline_project.rs"] mod
    /// inline_project;` in crate roots and in ordinary module files alike. Only
    /// the crate-root ones used to be placed: the walk carried a single base,
    /// the logical module directory, which for `coordinator.rs` is
    /// `src/coordinator/` rather than the `src/` the attribute is written
    /// against. The eight declarations in ordinary files therefore became
    /// `unplaced_module` gaps, and one such gap clears a target's
    /// `inventory_complete`.
    ///
    /// The ordinary `mod` declaration beside it is the control: it must keep
    /// resolving under the module directory, which is the base the two rules
    /// disagree about.
    #[test]
    fn a_path_attribute_in_a_module_file_resolves_against_that_file_directory() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"harness_path\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub mod coordinator;\n")
            .file(
                "src/coordinator.rs",
                "pub mod nested;\n\
                 #[cfg(test)]\n\
                 #[path = \"../test-support/harness.rs\"]\n\
                 mod harness;\n",
            )
            .file("src/coordinator/nested.rs", "pub fn nested() {}\n")
            .file("test-support/harness.rs", "pub struct Harness;\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();

        let placed = conn.prepare("SELECT topologies.crate_name, containers.container_path, sources.rel_path, containers.placement FROM rust_crate_topologies AS topologies JOIN rust_crate_containers AS containers USING(topology_id) JOIN rust_crate_container_sources AS sources USING(topology_id, container_path) WHERE containers.container_path LIKE 'crate::coordinator%' ORDER BY 2")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let gaps = conn
            .prepare("SELECT gap_kind, subject FROM rust_crate_gaps ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        assert!(
            placed.iter().any(|row| row
                == &(
                    "harness_path".to_string(),
                    "crate::coordinator::harness".to_string(),
                    "test-support/harness.rs".to_string(),
                    "path_attribute".to_string(),
                )),
            "placed={placed:?} gaps={gaps:?}"
        );
        assert!(
            placed.iter().any(|row| row
                == &(
                    "harness_path".to_string(),
                    "crate::coordinator::nested".to_string(),
                    "src/coordinator/nested.rs".to_string(),
                    "mod_declaration".to_string(),
                )),
            "placed={placed:?} gaps={gaps:?}"
        );
        assert!(
            !gaps.iter().any(|(kind, _)| kind == "unplaced_module"),
            "gaps={gaps:?}"
        );

        let incomplete = conn
            .prepare("SELECT crate_name, target_kind FROM rust_crate_topologies WHERE inventory_complete = 0 ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(incomplete, Vec::new(), "gaps={gaps:?}");
    }

    /// One file reached from two module files is two modules, not a gap.
    ///
    /// rustc compiles a file once per `mod` declaration that reaches it, and
    /// the results are distinct modules: `crate::coordinator::harness` and
    /// `crate::selector::harness` hold separate items with separate type
    /// identities. Owner decision of 2026-09-22: `duplicate_placement` is keyed
    /// on the module path, so two placements under two paths are two module
    /// rows. The container-source naming stays keyed on the file, because the
    /// package a file belongs to is a fact about the file.
    #[test]
    #[hardwon(
        "80645bcc16c2: one source file placed by two mod declarations has two module identities"
    )]
    fn one_file_reached_from_two_module_files_is_two_modules() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"shared_harness\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub mod coordinator;\npub mod selector;\n")
            .file(
                "src/coordinator.rs",
                "#[cfg(test)]\n#[path = \"../test-support/harness.rs\"]\nmod harness;\n",
            )
            .file(
                "src/selector.rs",
                "#[cfg(test)]\n#[path = \"../test-support/harness.rs\"]\nmod harness;\n",
            )
            .file("test-support/harness.rs", "pub struct Harness;\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let gaps = conn
            .prepare("SELECT gap_kind, subject FROM rust_crate_gaps ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(gaps, Vec::new(), "gaps={gaps:?}");

        let placements = conn
            .prepare(
                "SELECT source.container_path, source.rel_path, source.blob_id
                 FROM rust_crate_container_sources AS source
                 WHERE source.rel_path = 'test-support/harness.rs'
                 ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            placements
                .iter()
                .map(|(path, _, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec!["crate::coordinator::harness", "crate::selector::harness"],
            "placements={placements:?}"
        );
        assert_eq!(
            placements[0].2, placements[1].2,
            "both placements carry the one file's blob: {placements:?}"
        );

        // The naming authority is a fact about the file, so it is written once
        // however many modules the crate compiles the file into.
        let named: usize = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_file_naming WHERE rel_path = 'test-support/harness.rs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(named, 1);

        let complete: i64 = conn
            .query_row(
                "SELECT inventory_complete FROM rust_crate_topologies",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(complete, 1);
    }

    /// Two files under one module path is the ambiguity the crate rows cannot
    /// hold. It remains a `duplicate_placement` gap and also keeps the public
    /// module surface inventory open because that module cannot be inventoried.
    ///
    /// `mod harness;` in a `mod.rs` looks for `harness.rs` and `harness/mod.rs`
    /// alike. rustc rejects a crate that offers both; the walk reaches the one
    /// module path twice, from two files, and neither placement becomes a
    /// member. This is the case the module-path key still refuses, and it is
    /// pinned beside the two-module case so the difference stays visible.
    #[test]
    #[hardwon("80645bcc16c2: duplicate module paths from two files remain ambiguous")]
    fn one_module_path_placed_from_two_files_stays_a_duplicate_placement() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"ambiguous_file\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub mod harness;\n")
            .file("src/harness.rs", "pub struct FromFile;\n")
            .file("src/harness/mod.rs", "pub struct FromDirectory;\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let crate_key: String = conn
            .query_row(
                "SELECT hex(crate_key) FROM rust_crate_topologies WHERE crate_name='ambiguous_file'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let gaps = conn
            .prepare("SELECT gap_kind, subject FROM rust_crate_gaps ORDER BY 1, 2")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            gaps,
            vec![
                (
                    "duplicate_placement".to_string(),
                    "crate::harness".to_string()
                ),
                (
                    "open_export_inventory".to_string(),
                    format!("public-module-surface:{crate_key}:crate:type:harness")
                ),
            ]
        );
        let falsely_reachable: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_public_module_reachability AS reachability \
                 JOIN rust_crate_topologies AS topology USING (topology_id) \
                 WHERE topology.crate_key = reachability.target_crate_key \
                   AND reachability.target_module_path = 'crate::harness'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(falsely_reachable, 0);
    }

    #[test]
    #[hardwon("9888333a0d7f: enum glob imports need a persisted demand route")]
    fn crate_enum_glob_import_has_a_persisted_demand_route() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"enum_glob\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub enum DatumType { A, B } pub fn select() -> DatumType { use DatumType::*; A }",
            )
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let gaps = conn.prepare("SELECT gap_kind, subject, json(detail) FROM rust_crate_gaps ORDER BY gap_kind, subject")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let globs: i64 = conn
            .query_row("SELECT count(*) FROM rust_crate_glob_imports", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            globs, 1,
            "the enum's glob import must have a row for endpoint closure; gaps={gaps:?}"
        );
    }

    fn assert_fixture_rows(conn: &Connection) {
        fn strings(conn: &Connection, sql: &str) -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        }
        let exports = strings(
            conn,
            "SELECT t.crate_name || ' ' || t.target_kind || ' ' || e.module_path || ' ' || e.namespace || ' ' || e.name || ' ' || e.origin || ' ' || e.visibility FROM rust_crate_exports e JOIN rust_crate_topologies t USING(topology_id) ORDER BY t.crate_name,t.target_kind,e.module_path,e.namespace,e.name",
        );
        assert_eq!(
            exports,
            [
                "app bin crate type shared declaration private",
                "app bin crate value main declaration private",
                "app bin crate::shared value shared declaration public",
                "app lib crate type X reexport public",
                "app lib crate type a declaration public",
                "app lib crate type m declaration public",
                "app lib crate type shared declaration private",
                "app lib crate type tests declaration private",
                "app lib crate value X reexport public",
                "app lib crate value b reexport public",
                "app lib crate value first reexport public",
                "app lib crate value original glob_reexport public",
                "app lib crate value second reexport public",
                "app lib crate value third reexport public",
                "app lib crate::a value b declaration public",
                "app lib crate::a value original declaration public",
                "app lib crate::m value inside declaration public",
                "app lib crate::shared value shared declaration public",
                "app lib crate::tests value test_only declaration public",
                "dep lib crate type X declaration public",
                "dep lib crate type on declaration public",
                "dep lib crate value X declaration public",
                "dep lib crate::on value enabled declaration public",
                "dep/src/off.rs detached crate value disabled declaration public",
                "detached.rs detached crate value detached declaration public",
                "helper lib crate type H declaration public",
                "helper lib crate value H declaration public",
                "x test crate value x declaration private"
            ]
        );
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_exports e WHERE NOT EXISTS (SELECT 1 FROM source_native_declaration_bridges b JOIN resolution_semantic_sites s ON s.blob_id=b.blob_id AND s.source_site=b.source_site WHERE b.blob_id=e.declaration_blob_id AND b.source_site=e.declaration_site AND s.semantic_role='definition')", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        let modules = strings(
            conn,
            "SELECT t.crate_name || '/' || t.target_kind || ' ' || m.container_path || ' ' || s.rel_path || ' ' || m.placement || ' ' || s.scope_ordinal FROM rust_crate_topologies t JOIN rust_crate_containers m USING(topology_id) JOIN rust_crate_container_sources s USING(topology_id, container_path) ORDER BY 1",
        );
        let mut expected = vec![
            "app/bin crate app/src/main.rs root 0",
            "app/bin crate::shared app/src/shared.rs path_attribute 0",
            "app/lib crate app/src/lib.rs root 0",
            "app/lib crate::a app/src/a.rs mod_declaration 0",
            "app/lib crate::m app/src/lib.rs inline 1",
            "app/lib crate::shared app/src/shared.rs path_attribute 0",
            "app/lib crate::tests app/src/lib.rs inline 2",
            "dep/lib crate dep/src/lib.rs root 0",
            "dep/lib crate::on dep/src/on.rs mod_declaration 0",
            "dep/src/off.rs/detached crate dep/src/off.rs root 0",
            "detached.rs/detached crate detached.rs root 0",
            "helper/lib crate helper/src/lib.rs root 0",
            "x/test crate app/tests/x.rs root 0",
        ];
        expected.sort_unstable();
        assert_eq!(modules, expected);
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || d.extern_name || ' ' || d.boundary || ' ' || d.dependency_kind || ' ' || target.crate_name FROM rust_crate_dependencies d JOIN rust_crate_topologies t USING(topology_id) JOIN rust_crate_topologies target ON target.crate_key=d.dependency_crate_key ORDER BY 1"
            ),
            [
                "app/bin app workspace normal app",
                "app/bin dep workspace normal dep",
                "app/bin helper workspace dev helper",
                "app/lib dep workspace normal dep",
                "app/lib helper workspace dev helper",
                "x/test app workspace normal app",
                "x/test dep workspace normal dep",
                "x/test helper workspace dev helper"
            ]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || i.module_path || ' ' || i.namespace || ' ' || i.bound_name || ' ' || i.import_ordinal || ' ' || i.binder_scope || ' ' || target.crate_name || ' ' || i.target_module_path || ' ' || i.target_name FROM rust_crate_imports i JOIN rust_crate_topologies t USING(topology_id) JOIN rust_crate_topologies target ON target.crate_key=i.target_crate_key ORDER BY 1"
            ),
            [
                "app/lib crate type X 5 0 dep crate X",
                "app/lib crate value X 5 0 dep crate X",
                "app/lib crate value b 1 0 app crate::a original",
                "app/lib crate value c 6 0 app crate::a b",
                "app/lib crate value first 2 0 app crate::a b",
                "app/lib crate value second 3 0 app crate::a b",
                "app/lib crate value third 4 0 app crate::a b",
                "x/test crate type H 0 0 helper crate H",
                "x/test crate value H 0 0 helper crate H"
            ]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || i.module_path || ' ' || i.import_ordinal || ' ' || i.binder_scope || ' ' || i.target_module_path FROM rust_crate_glob_imports i JOIN rust_crate_topologies t USING(topology_id) ORDER BY 1"
            ),
            ["app/lib crate 0 0 crate::a", "app/lib crate::a 0 0 crate"]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || r.module_path || ' ' || r.bound_name || ' ' || target.crate_name || ' ' || r.target_module_path || ' ' || r.target_name || ' ' || r.visibility FROM rust_crate_reexport_routes r JOIN rust_crate_topologies t USING(topology_id) JOIN rust_crate_topologies target ON target.crate_key=r.target_crate_key ORDER BY 1"
            ),
            [
                "app/lib crate X dep crate X public",
                "app/lib crate b app crate::a original public",
                "app/lib crate first app crate::a b public",
                "app/lib crate second app crate::a b public",
                "app/lib crate third app crate::a b public"
            ]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || ' ' || g.gap_kind || ' ' || g.subject FROM rust_crate_gaps g JOIN rust_crate_topologies t USING(topology_id) ORDER BY 1"
            ),
            ["dep inactive_placement crate::off"]
        );
        assert_eq!(
            strings(
                conn,
                "SELECT t.crate_name || '/' || t.target_kind || ' ' || coalesce(m.rel_path,'detached') FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) LEFT JOIN workspace_file_versions m ON m.file_version_id=v.manifest_file_version_id WHERE v.valid_until IS NULL ORDER BY 1"
            ),
            [
                "app/bin app/Cargo.toml",
                "app/lib app/Cargo.toml",
                "dep/lib dep/Cargo.toml",
                "dep/src/off.rs/detached detached",
                "detached.rs/detached detached",
                "helper/lib helper/Cargo.toml",
                "x/test app/Cargo.toml"
            ]
        );
        let topologies = conn.prepare("SELECT crate_name, json(cfg_atoms), edition, inventory_complete, publication_state, length(topology_digest), length(export_surface_digest) FROM rust_crate_topologies").unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, bool>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(topologies.len(), 7);
        for (name, cfg, edition, complete, state, topology_bytes, surface_bytes) in topologies {
            let mut expected_cfg = brokk_bifrost_rust::cfg::default_cfg_atoms();
            if name == "dep" {
                expected_cfg.insert("feature = \"on\"".into());
            }
            assert_eq!(
                serde_json::from_str::<BTreeSet<String>>(&cfg).unwrap(),
                expected_cfg
            );
            assert_eq!(
                (
                    edition.as_str(),
                    complete,
                    state.as_str(),
                    topology_bytes,
                    surface_bytes
                ),
                ("2021", true, "complete", 32, 32)
            );
        }
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    #[test]
    #[hardwon("eea3f7fb1831: public use bindings were filtered out of crate import publication")]
    fn crate_rows_derive_exports_imports_and_public_invalidation() {
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let before = {
            let conn = store.read_conn().unwrap();
            assert_fixture_rows(&conn);
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        };
        let file = fixture.file("dep/src/lib.rs");
        file.write("pub struct Y(pub u8); #[cfg(feature = \"on\")] pub mod on; #[cfg(feature = \"off\")] pub mod off;").unwrap();
        let updated = analyzer.update(&BTreeSet::from([file]));
        let conn = updated.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            before + 4
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_versions WHERE valid_until IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            4
        );
        let incremental = current_crate_digests(&conn);
        drop(conn);
        let cold = fixture.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            incremental,
            current_crate_digests(&cold.store().unwrap().read_conn().unwrap())
        );
    }

    #[test]
    fn crate_reconcile_statement_cost_scales_with_crates_and_modules() {
        fn measure(crates: usize) -> usize {
            let mut fixture = InlineTestProject::new();
            let members = (0..crates)
                .map(|index| format!("\"p{index}\""))
                .collect::<Vec<_>>()
                .join(",");
            fixture = fixture.file("Cargo.toml", format!("[workspace]\nmembers=[{members}]\n"));
            for index in 0..crates {
                fixture = fixture.file(
                    format!("p{index}/Cargo.toml"),
                    format!("[package]\nname=\"p{index}\"\nversion=\"0.1.0\"\nedition=\"2021\"\n"),
                );
                let root = (0..8)
                    .map(|module| format!("pub mod m{module};\n"))
                    .collect::<String>();
                fixture = fixture.file(format!("p{index}/src/lib.rs"), root);
                for module in 0..8 {
                    fixture = fixture.file(
                        format!("p{index}/src/m{module}.rs"),
                        format!("pub fn f{index}_{module}() {{}}"),
                    );
                }
            }
            let fixture = fixture.build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let snapshot = store.conn.execute_fixture(|conn| -> Result<_> {
                let snapshot = conn.query_row("SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'", [], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)))?;
                conn.execute("DELETE FROM rust_crate_versions", [])?;
                conn.execute(brokk_bifrost_analysis::analyzer::store::unit_summaries::DELETE_LANGUAGE_VERSIONS_SQL, ["rust"])?;
                conn.execute(brokk_bifrost_core::cache_gc::DELETE_UNBOUND_SUMMARIES_SQL, [])?;
                conn.execute(DELETE_UNBOUND_TOPOLOGIES_SQL, [])?;
                Ok(snapshot)
            }).unwrap();
            let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            *store.crate_statement_counter.lock().unwrap() = Some(counter.clone());
            let snapshot = WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(snapshot.0),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    snapshot.1,
                ),
                revision: snapshot.2,
            };
            store.reconcile_rust_crates(&snapshot).unwrap();
            *store.crate_statement_counter.lock().unwrap() = None;
            assert_eq!(
                std::sync::Arc::strong_count(&counter),
                1,
                "reader/writer trace did not release request state"
            );
            counter.load(std::sync::atomic::Ordering::Relaxed)
        }
        let small = measure(4);
        let large = measure(8);
        eprintln!("reconcile statements: 4 crates/36 modules={small}, 8 crates/72 modules={large}");
        assert!(
            small > 100,
            "trace must include actual derivation statements: {small}"
        );
        assert!(
            large > small && large < small * 3,
            "expected linear growth, measured {small} -> {large}"
        );
    }

    #[test]
    fn crate_declaration_derivation_work_scales_with_blob_rows_not_container_product() {
        fn measure(module_count: usize) -> (usize, i64) {
            let mut source = String::new();
            for module in 0..module_count {
                source.push_str(&format!("pub mod m{module} {{\n"));
                for declaration in 0..32 {
                    source.push_str(&format!("pub fn f{module}_{declaration}() {{}}\n"));
                }
                source.push_str("}\n");
            }
            let fixture = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[package]\nname=\"scale\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file("src/lib.rs", source)
                .build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            derivation::prepare_tables(&conn).unwrap();
            let (topology_id, cfg): (i64, String) = conn
                .query_row(
                    "SELECT topology_id, json(cfg_atoms) FROM rust_crate_topologies WHERE crate_name='scale' AND publication_state='complete' ORDER BY topology_id DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let members = conn
                .prepare("SELECT sources.container_path, sources.blob_id, sources.scope_ordinal, sources.rel_path, containers.placement, sources.parent_container_path FROM rust_crate_container_sources AS sources JOIN rust_crate_containers AS containers USING(topology_id, container_path) WHERE sources.topology_id=?1 AND containers.kind='module'")
                .unwrap()
                .query_map([topology_id], |row| {
                    Ok(Member {
                        module_path: row.get(0)?,
                        blob_id: row.get(1)?,
                        scope: row.get(2)?,
                        rel_path: row.get(3)?,
                        placement: row.get(4)?,
                        parent_path: row.get(5)?,
                    })
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for member in members {
                conn.execute(
                    derivation::SQL_CR_MEMBERS_1,
                    params![
                        member.module_path,
                        member.blob_id,
                        member.scope,
                        member.rel_path,
                        member.placement
                    ],
                )
                .unwrap();
            }
            conn.execute(derivation::SQL_CR_MEMBERS_2, []).unwrap();
            conn.execute(derivation::POPULATE_MEMBER_BLOBS_SQL, [])
                .unwrap();
            conn.execute(derivation::POPULATE_SCOPES_SQL, []).unwrap();
            let steps = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = steps.clone();
            conn.progress_handler(
                1,
                Some(move || {
                    observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    false
                }),
            )
            .unwrap();
            conn.execute(derivation::SOURCE_DECLARATIONS_SQL, [cfg])
                .unwrap();
            conn.progress_handler(0, None::<fn() -> bool>).unwrap();
            let rows = conn
                .query_row("SELECT count(*) FROM cr_source_declarations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            (steps.load(std::sync::atomic::Ordering::Relaxed), rows)
        }

        let small = measure(8);
        let large = measure(16);
        eprintln!("declaration candidate work: 8 modules={small:?}, 16 modules={large:?}");
        assert_eq!(large.1, small.1 * 2, "{small:?} -> {large:?}");
        assert!(
            large.0 * (small.1 as usize) < small.0 * (large.1 as usize) * 6 / 5,
            "VM work per declaration candidate must stay within 20 percent: {small:?} -> {large:?}"
        );
    }

    #[test]
    #[hardwon(
        "#5133: pending ancestors behind complete facades must respect revisions and SCC forcing"
    )]
    fn pending_ancestor_readiness_is_revision_scoped_and_cycle_safe() {
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute_batch(CREATE_PENDING_CRATES_SQL).unwrap();
        let workspace = "a".repeat(64);
        let other_workspace = "b".repeat(64);
        // consumer -> facade -> (core <-> peer). Decoy is pending but has no
        // selected edge; only historical/future/foreign versions reach it.
        for (topology, key) in [(1_u8, 1_u8), (2, 2), (3, 3), (4, 4), (5, 5), (6, 3)] {
            conn.execute(
                "INSERT INTO rust_crate_topologies VALUES(?1, ?2, ?3, 'test',
                 'lib', 'sample', '2021', 'std', jsonb('[]'), 1, zeroblob(32), 'complete', 0)",
                params![
                    i64::from(topology),
                    [topology; 32].as_slice(),
                    [key; 32].as_slice()
                ],
            )
            .unwrap();
        }
        for (topology, dependency) in [(1, 2_u8), (2, 3), (3, 4), (4, 3), (6, 5)] {
            conn.execute(
                SQL_RUST_CRATE_DEPENDENCIES_12,
                params![
                    topology,
                    "dep",
                    "workspace",
                    [dependency; 32].as_slice(),
                    "normal"
                ],
            )
            .unwrap();
        }
        for (owner, lang, generation, key, from, until, topology) in [
            (&workspace, "rust", 0, 1_u8, 1, None, 1),
            (&workspace, "rust", 0, 2, 1, None, 2),
            (&workspace, "rust", 0, 3, 2, Some(3), 3),
            (&workspace, "rust", 0, 4, 1, None, 4),
            (&workspace, "rust", 0, 5, 1, None, 5),
            (&workspace, "rust", 0, 3, 1, Some(2), 6),
            (&workspace, "rust", 0, 3, 3, None, 6),
            (&other_workspace, "rust", 0, 3, 1, None, 6),
            (&workspace, "rust", 1, 3, 1, None, 6),
            (&workspace, "go", 0, 3, 1, None, 6),
        ] {
            conn.execute(
                "INSERT INTO rust_crate_versions VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
                params![
                    owner,
                    lang,
                    generation,
                    [key; 32].as_slice(),
                    from,
                    until,
                    topology
                ],
            )
            .unwrap();
        }
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (key, component) in [(1_u8, 1_u8), (3, 3), (4, 3), (5, 5)] {
                conn.execute(
                    INSERT_PENDING_CRATE_SQL,
                    params![[key; 32].as_slice(), [component; 32].as_slice()],
                )
                .unwrap();
            }
            let blocked = |revision| {
                conn.prepare(SQL_RUST_CRATE_PENDING_ANCESTORS)
                    .unwrap()
                    .query_map(params![workspace, 0, revision], |row| {
                        row.get::<_, Vec<u8>>(0)
                    })
                    .unwrap()
                    .map(|row| crate_key_from_row(row.unwrap()).unwrap())
                    .collect::<HashSet<_>>()
            };
            assert_eq!(blocked(2), HashSet::from([[1; 32]]), "{state:?}");
            for revision in [1, 3] {
                assert_eq!(
                    blocked(revision),
                    HashSet::from([[1; 32], [3; 32], [4; 32]]),
                    "{state:?} revision {revision}"
                );
            }
            // Equal producer output leaves the facade complete. Once the SCC
            // finishes, the consumer is ready without enqueueing that facade.
            for key in [3_u8, 4] {
                conn.execute(
                    "DELETE FROM temp.rust_crate_pending_keys WHERE crate_key=?1",
                    [[key; 32].as_slice()],
                )
                .unwrap();
            }
            assert_eq!(blocked(2), HashSet::new(), "{state:?}");
            // Changed producer output enqueues the facade, blocking consumer
            // directly until that facade has published its new surface.
            conn.execute(
                INSERT_PENDING_CRATE_SQL,
                params![[2_u8; 32].as_slice(), [2_u8; 32].as_slice()],
            )
            .unwrap();
            assert_eq!(blocked(2), HashSet::from([[1; 32]]), "{state:?}");
            conn.execute("DELETE FROM temp.rust_crate_pending_keys", [])
                .unwrap();
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4460: module-self route views added an automatic covering index"
    )]
    fn crate_derivation_statements_have_indexed_plans_in_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned_queries;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id, lang, generation, revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        prepare_pin_context(&conn).unwrap();
        let (id, key, cfg): (i64, Vec<u8>, String) = conn.query_row("SELECT topology_id, crate_key, json(cfg_atoms) FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        let members = conn.prepare("SELECT container_path, blob_id, scope_ordinal, rel_path, placement, parent_container_path FROM rust_crate_containers JOIN rust_crate_container_sources USING(topology_id, container_path) WHERE topology_id=?1").unwrap().query_map([id], |row| Ok(Member { module_path:row.get(0)?, blob_id:row.get(1)?, scope:row.get(2)?, rel_path:row.get(3)?, placement:row.get(4)?, parent_path:row.get(5)? })).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        for member in members {
            conn.execute(
                derivation::SQL_CR_MEMBERS_1,
                params![
                    member.module_path,
                    member.blob_id,
                    member.scope,
                    member.rel_path,
                    member.placement
                ],
            )
            .unwrap();
        }
        conn.execute(derivation::SQL_CR_MEMBERS_2, []).unwrap();
        conn.execute(derivation::POPULATE_MEMBER_BLOBS_SQL, [])
            .unwrap();
        conn.execute(derivation::POPULATE_SCOPES_SQL, []).unwrap();
        conn.execute(derivation::INSERT_IDENTITY_SQL, [&key])
            .unwrap();
        conn.execute(
            "INSERT INTO cr_foreign SELECT crate_key, topology_id, crate_name FROM rust_crate_topologies WHERE topology_id <> ?1",
            [id],
        )
        .unwrap();
        conn.execute(derivation::FOREIGN_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::SOURCE_DECLARATIONS_SQL, [&cfg])
            .unwrap();
        conn.execute(derivation::RESTRICTION_INPUTS_SQL, [])
            .unwrap();
        conn.execute(derivation::RESTRICTIONS_SQL, []).unwrap();
        conn.execute(derivation::DECLARATIONS_SQL, []).unwrap();
        conn.execute(derivation::SQL_CR_EXPORTS_4, []).unwrap();
        conn.execute(derivation::ENUM_CONTAINERS_SQL, []).unwrap();
        conn.execute(derivation::ENUM_VARIANTS_SQL, []).unwrap();
        conn.execute("INSERT INTO cr_dependencies SELECT d.extern_name, d.dependency_crate_key, t.topology_id FROM rust_crate_dependencies d LEFT JOIN rust_crate_topologies t ON t.crate_key=d.dependency_crate_key WHERE d.topology_id=?1", [id]).unwrap();
        conn.execute(derivation::CONTAINERS_SQL, []).unwrap();
        conn.execute(derivation::CLOSE_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::FOREIGN_GLOB_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::CLOSE_GLOB_STEPS_SQL, []).unwrap();
        conn.execute(derivation::SQL_CR_SOURCE_IMPORTS_5, [&cfg])
            .unwrap();
        conn.execute(derivation::MODULE_DECLARATIONS_SQL, [])
            .unwrap();
        conn.execute(derivation::ROOT_SOURCES_SQL, []).unwrap();
        conn.execute(&derivation::IMPL_SOURCES_SQL, []).unwrap();
        derivation::derive_bindings_for_plan(&conn, "2021").unwrap();
        conn.execute(derivation::ROUTES_SQL.as_str(), []).unwrap();
        conn.execute(derivation::LOCAL_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::CLEAR_REEXPORT_CLOSURE_SQL, [])
            .unwrap();
        conn.execute(derivation::CLOSE_REEXPORT_STEPS_SQL, [])
            .unwrap();
        conn.execute(derivation::LOCAL_GLOB_STEPS_SQL, []).unwrap();
        conn.execute(derivation::CLEAR_GLOB_CLOSURE_SQL, [])
            .unwrap();
        conn.execute(derivation::CLOSE_GLOB_STEPS_SQL, []).unwrap();
        conn.execute(derivation::DEPENDENCY_EXPORTS_SQL, [&key])
            .unwrap();
        conn.execute(derivation::EXPORT_SOURCES_SQL, []).unwrap();
        conn.execute_batch(
            "DELETE FROM cr_export_delta; DELETE FROM cr_export_delta_next;
             INSERT INTO cr_export_delta SELECT * FROM cr_exports;",
        )
        .unwrap();
        let (workspace, generation, revision): (String, i64, i64) = conn
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let (digest, surface, epoch): (Vec<u8>,Vec<u8>,String) = conn.query_row("SELECT topology_digest,export_surface_digest,producer_epoch FROM rust_crate_topologies WHERE topology_id=?1", [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        let root_blob: i64 = conn.query_row("SELECT blob_id FROM rust_crate_containers JOIN rust_crate_container_sources USING(topology_id, container_path) WHERE topology_id=?1 AND container_path='crate'", [id], |row| row.get(0)).unwrap();
        let root_oid: String = conn
            .query_row(SQL_BLOBS_8, [root_blob], |row| row.get(0))
            .unwrap();
        let manifest: i64 = conn
            .query_row(
                "SELECT manifest_file_version_id FROM rust_crate_versions WHERE topology_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        let (dependency, dependency_id): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT crate_key,topology_id FROM rust_crate_topologies WHERE crate_name='dep'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let helper: Vec<u8> = conn
            .query_row(
                "SELECT crate_key FROM rust_crate_topologies WHERE crate_name='helper'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        for pending in [&key, &dependency, &helper] {
            conn.execute(INSERT_PENDING_CRATE_SQL, params![pending, pending])
                .unwrap();
        }
        conn.execute_batch("INSERT INTO temp.rust_schedule_targets
            (unit_id,crate_key,manifest_path,root_path,target_kind,crate_name,edition,cfg,features,inventory_complete,pending)
            SELECT topology_id,crate_key,'','',target_kind,crate_name,edition,json(cfg_atoms),'[]',inventory_complete,1
            FROM rust_crate_topologies WHERE topology_id IN (SELECT topology_id FROM rust_crate_versions WHERE valid_until IS NULL);
            INSERT INTO temp.rust_schedule_dependencies
            SELECT targets.crate_key, row_number() OVER (PARTITION BY targets.crate_key ORDER BY deps.extern_name), deps.extern_name, deps.dependency_kind, deps.dependency_crate_key
            FROM temp.rust_schedule_targets AS targets JOIN rust_crate_dependencies AS deps ON deps.topology_id = targets.unit_id;
            INSERT INTO temp.unit_schedule_units SELECT unit_id FROM temp.rust_schedule_targets;
            INSERT INTO temp.unit_schedule_edges
            SELECT DISTINCT owner.unit_id, dependency.unit_id, 1 FROM temp.rust_schedule_dependencies AS edges
            JOIN temp.rust_schedule_targets AS owner ON owner.crate_key = edges.crate_key
            JOIN temp.rust_schedule_targets AS dependency ON dependency.crate_key = edges.dependency_key;
            INSERT INTO temp.rust_schedule_pending_order(unit_id) SELECT unit_id FROM temp.rust_schedule_targets ORDER BY unit_id;") .unwrap();
        unit_schedule::build(&conn).unwrap();
        conn.execute_batch("INSERT INTO temp.rust_schedule_live SELECT crate_key,topology_id,export_surface_digest FROM rust_crate_topologies WHERE topology_id IN (SELECT topology_id FROM rust_crate_versions WHERE valid_until IS NULL);
            INSERT INTO temp.rust_schedule_wave SELECT unit_id,0 FROM temp.unit_schedule_units;
            INSERT INTO temp.rust_schedule_wave_order(unit_id) SELECT unit_id FROM temp.unit_schedule_units ORDER BY unit_id;").unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let blocked = conn
                .prepare(SQL_RUST_CRATE_PENDING_ANCESTORS)
                .unwrap()
                .query_map(params![workspace, generation, revision], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(blocked.as_slice(), std::slice::from_ref(&key), "{state:?}");
            for mut pin in pinned_queries().into_iter().filter(|pin| {
                pin.name.starts_with("rust_crate_") || pin.name.starts_with("unit_schedule_")
            }) {
                use rusqlite::types::Value::{Blob, Integer, Null, Text};
                let text = |s: &str| Text(s.to_owned());
                if !pin.params.is_empty() {
                    pin.params = match pin.name.as_str() {
                        "rust_crate_replaced_blob_id" => {
                            vec![text(&root_oid), text("rust"), Integer(generation), Blob(Vec::new())]
                        }
                        "rust_crate_reinsert_blob" => vec![
                            Integer(root_blob),
                            text(&root_oid),
                            text("rust"),
                            Integer(generation),
                            Blob(Vec::new()),
                        ],
                        "rust_crate_module_walk" => {
                            vec![text("app/src/lib.rs"), text(&cfg), text("[]")]
                        }
                        "rust_crate_item_macro_decisions" => vec![text("[]"), text("[]")],
                        "rust_crate_source_declarations"
                        | "rust_crate_macro_items"
                        | "rust_crate_derivation_sql_cr_source_imports_5"
                        | "rust_crate_unknown_exports"
                        | "rust_crate_extern_crate_alias_dependencies" => vec![text(&cfg)],
                        "rust_crate_import_routes" => vec![Blob(key.clone()), text("2021")],
                        "rust_crate_insert_pending_key" => {
                            vec![Blob(key.clone()), Blob(key.clone())]
                        }
                        "rust_crate_pending_ancestors" => {
                            vec![text(&workspace), Integer(generation), Integer(revision)]
                        }
                        "rust_crate_export_fixpoint"
                        | "rust_crate_derivation_sql_cr_reexports_6"
                        | "rust_crate_dependency_exports"
                        | "rust_crate_insert_identity" => vec![Blob(key.clone())],
                        "rust_crate_schedule_staged_target" => vec![Integer(id)],
                        "rust_crate_schedule_staged_dependencies" | "rust_crate_schedule_live_surface" => vec![Blob(key.clone())],
                        "rust_crate_schedule_wave_unit" => vec![Integer(1)],
                        "rust_crate_insert_foreign" => {
                            vec![Blob(dependency.clone()), Integer(dependency_id)]
                        }
                        "rust_crate_reconcile_sql_workspace_file_versions_2" => {
                            vec![text(&workspace), Integer(generation), Integer(revision)]
                        }
                        "rust_crate_reconcile_sql_rust_crate_containers_5" => vec![Integer(id)],
                        "rust_crate_reconcile_sql_rust_crate_versions_6" => {
                            vec![text(&workspace), Integer(generation)]
                        }
                        "rust_crate_reconcile_sql_rust_crate_versions_16"
                        | "rust_crate_reconcile_sql_rust_crate_versions_withdraw" => vec![
                            Integer(revision),
                            text(&workspace),
                            Integer(generation),
                            Blob(key.clone()),
                        ],
                        "rust_crate_reconcile_sql_blobs_8" => vec![Integer(root_blob)],
                        "rust_crate_reconcile_sql_rust_crate_topologies_9" => {
                            vec![Blob(digest.clone())]
                        }
                        "rust_crate_reconcile_sql_rust_crate_topologies_10" => vec![
                            Blob(digest.clone()),
                            Blob(key.clone()),
                            text(&epoch),
                            text("lib"),
                            text("app"),
                            text("2021"),
                            text(&cfg),
                            Integer(1),
                            text("std"),
                            Integer(0),
                        ],
                        "rust_crate_reconcile_sql_root_inner_attributes" => {
                            vec![Integer(root_blob)]
                        }
                        "rust_crate_insert_naming" => {
                            vec![Integer(id), text("app/src/lib.rs"), text("[]"), text("[]")]
                        }
                        "rust_crate_insert_enum_container" => vec![
                            Integer(id),
                            text("crate::Shape"),
                            text("enum"),
                            text("enum_declaration"),
                        ],
                        "rust_crate_insert_enum_source" => vec![
                            Integer(id),
                            text("crate::Shape"),
                            Integer(root_blob),
                            Null,
                            text("app/src/lib.rs"),
                            text("declared"),
                            Integer(0),
                            text("crate"),
                        ],
                        "rust_crate_insert_module" => {
                            vec![Integer(id), text("crate"), text("root")]
                        }
                        "rust_crate_public_module_reachability_insert" => {
                            vec![Integer(id), Blob(dependency.clone()), text("crate")]
                        }
                        "rust_crate_reconcile_sql_rust_crate_containers_11" => vec![
                            Integer(id),
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            text("app/src/lib.rs"),
                            text("root"),
                            Null,
                        ],
                        "rust_crate_reconcile_sql_rust_crate_dependencies_12" => vec![
                            Integer(id),
                            text("dep"),
                            text("workspace"),
                            Blob(dependency.clone()),
                            text("normal"),
                        ],
                        "rust_crate_reconcile_sql_rust_crate_gaps_13"
                        | "rust_crate_derivation_sql_rust_crate_gaps_21" => vec![
                            Integer(dependency_id),
                            text("inactive_placement"),
                            text("crate::off"),
                            text("{\"activation\":0,\"path\":\"dep/src/off.rs\"}"),
                        ],
                        "rust_crate_reconcile_sql_rust_crate_topologies_14" => {
                            vec![Blob(surface.clone()), Integer(id)]
                        }
                        "rust_crate_reconcile_sql_reconciliation_previous" => vec![
                            text(&workspace),
                            Integer(generation),
                            text(derivation_version()),
                        ],
                        "rust_crate_reconcile_sql_workspace_file_changes_between" => vec![
                            text(&workspace),
                            Integer(generation),
                            Integer(revision - 1),
                            Integer(revision),
                        ],
                        "rust_crate_reconcile_sql_rust_crate_versions_15" => {
                            vec![text(&workspace), Integer(generation), Blob(key.clone())]
                        }
                        "rust_crate_reconcile_sql_rust_crate_versions_17" => vec![
                            text(&workspace),
                            Integer(generation),
                            Blob(key.clone()),
                            Integer(revision),
                            Integer(manifest),
                            Integer(id),
                        ],
                        "rust_crate_derivation_sql_cr_members_1" => vec![
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            text("app/src/lib.rs"),
                            text("root"),
                        ],
                        "rust_crate_derivation_sql_cr_dependencies_3" => vec![
                            text("dep"),
                            Blob(dependency.clone()),
                            Integer(dependency_id),
                        ],
                        "rust_crate_derivation_sql_rust_crate_exports_17" => vec![
                            Integer(id),
                            text("crate"),
                            text("type"),
                            text("a"),
                            text("declaration"),
                            text("public"),
                            Null,
                            Integer(root_blob),
                            Integer(0),
                            Blob(key.clone()),
                            text("crate"),
                            text("a"),
                        ],
                        "rust_crate_derivation_sql_rust_crate_reexport_routes_18" => vec![
                            Integer(id),
                            text("crate"),
                            text("X"),
                            Blob(dependency.clone()),
                            text("crate"),
                            text("X"),
                            text("public"),
                            Null,
                        ],
                        "rust_crate_derivation_sql_rust_crate_imports_19" => vec![
                            Integer(id),
                            text("crate"),
                            text("value"),
                            text("c"),
                            Integer(root_blob),
                            Integer(6),
                            Integer(0),
                            Blob(key.clone()),
                            text("crate::a"),
                            text("b"),
                        ],
                        "rust_crate_derivation_sql_rust_crate_glob_imports_20" => vec![
                            Integer(id),
                            text("crate::a"),
                            Integer(root_blob),
                            Integer(0),
                            Integer(0),
                            Blob(key.clone()),
                            text("crate"),
                        ],
                        // The `UnexpandedImplMacro` gap origin code the
                        // statement excludes undecided frontiers by.
                        "rust_crate_open_export_inventory" => vec![Integer(
                            brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin::Extracted(
                                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro,
                                ),
                            ),
                        ), text(&cfg)],
                        "rust_crate_trait_impls_insert" => vec![
                            Integer(id),
                            Integer(root_blob),
                            Integer(0),
                            text("src/lib.rs"),
                            Integer(root_blob),
                            Integer(1),
                            text("src/lib.rs"),
                            Integer(root_blob),
                            Integer(2),
                            text("src/lib.rs"),
                            Integer(0),
                        ],
                        "rust_crate_inherent_impls_insert" => vec![
                            Integer(id), Integer(root_blob), Integer(0), text("src/lib.rs"),
                            Integer(root_blob), Integer(2), text("src/lib.rs"), Integer(0),
                        ],
                        "rust_crate_unresolved_inherent_impls_insert" => vec![
                            Integer(id), text("Unbound"), Integer(root_blob), Integer(3),
                            text("src/lib.rs"), Null, text("unbound"), text("crate::elsewhere"),
                        ],
                        "rust_crate_decided_item_macros_insert" => {
                            vec![Integer(id), Integer(root_blob), Integer(0), text("always")]
                        }
                        "rust_crate_unresolved_trait_impls_insert" => vec![
                            Integer(id),
                            text("trait"),
                            text("Unbound"),
                            Integer(root_blob),
                            Integer(3),
                            text("src/lib.rs"),
                            Null,
                            text("unbound"),
                            text("crate::elsewhere"),
                            Null,
                            Null,
                            Null,
                            text("crate"),
                        ],
                        "rust_crate_root_references_insert" => vec![
                            Integer(id),
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            Integer(0),
                            Blob(key.clone()),
                            text("crate"),
                            text("target"),
                        ],
                        "rust_crate_glob_reexport_derive" => vec![Blob(key.clone())],
                        "rust_crate_glob_reexport_insert" => vec![
                            Integer(id),
                            text("crate"),
                            Blob(dependency.clone()),
                            text("crate"),
                            text("public"),
                            Null,
                        ],
                        "rust_crate_glob_reexport_routes_target" => {
                            vec![Blob(dependency.clone()), text("crate")]
                        }
                        "rust_crate_named_reexport_targets" => {
                            vec![Integer(id), text("crate"), text("value"), text("b")]
                        }
                        "rust_crate_imports_binder" => vec![
                            Integer(id),
                            text("crate"),
                            Integer(root_blob),
                            Integer(0),
                            text("c"),
                        ],
                        "rust_crate_imports_target" => {
                            vec![Blob(helper.clone()), text("crate"), text("H")]
                        }
                        "rust_crate_exports_declaration" => vec![Integer(root_blob), Integer(0)],
                        "rust_crate_reexport_routes_target" => {
                            vec![Blob(dependency.clone()), text("crate"), text("X")]
                        }
                        "rust_crate_exports_reachable" => {
                            vec![Integer(id), text("crate"), text("X")]
                        }
                        "rust_crate_binding_provenance_insert" => vec![Integer(id),text("crate"),Integer(root_blob),Integer(0),text("type"),text("X"),Integer(0),Blob(dependency.clone()),text("crate"),Integer(0),Integer(0),text("X"),Blob(dependency.clone()),text("crate"),text("X")],
                        "rust_crate_binding_provenance_read" => vec![Integer(0),Integer(id)],
                        other => panic!("add populated production-shaped bindings for {other}"),
                    };
                }
                let plan = explain_pin(&conn, &pin);
                if pin.name == "unit_schedule_edges" {
                    assert!(
                        plan.iter()
                            .any(|row| row.contains("SEARCH edges USING PRIMARY KEY (unit_id=?)")),
                        "{state:?}: {plan:?}"
                    );
                    assert!(
                        !plan
                            .iter()
                            .any(|row| row.contains("AUTOMATIC") || row.contains("SCAN edges")),
                        "{state:?}: {plan:?}"
                    );
                }
                if matches!(
                    pin.name.as_str(),
                    "rust_crate_schedule_ready" | "rust_crate_schedule_force"
                ) {
                    assert!(
                        plan.iter()
                            .any(|row| row.contains("rust_schedule_targets_pending")),
                        "{state:?}: {plan:?}"
                    );
                    assert!(
                        plan.iter()
                            .any(|row| row.contains("SEARCH edge USING PRIMARY KEY (crate_key=?)")),
                        "{state:?}: {plan:?}"
                    );
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?}: {plan:?}"
                    );
                }
                let required_seek = match pin.name.as_str() {
                    "rust_crate_binding_provenance_read" => Some(
                        "SEARCH routes USING COVERING INDEX rust_crate_binding_provenance_source (topology_id=? AND blob_id=?)",
                    ),
                    "rust_crate_schedule_staged_target" => {
                        Some("SEARCH temp.rust_schedule_targets USING INTEGER PRIMARY KEY")
                    }
                    "rust_crate_schedule_staged_dependencies" => Some(
                        "SEARCH temp.rust_schedule_dependencies USING PRIMARY KEY (crate_key=?)",
                    ),
                    "rust_crate_schedule_live_surface" => {
                        Some("SEARCH temp.rust_schedule_live USING PRIMARY KEY (crate_key=?)")
                    }
                    "rust_crate_schedule_wave_unit" => {
                        Some("SEARCH ordered USING INTEGER PRIMARY KEY")
                    }
                    "unit_schedule_order" => Some("unit_schedule_components_component"),
                    _ => None,
                };
                if let Some(seek) = required_seek {
                    assert!(
                        plan.iter().any(|row| row.contains(seek)),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_pending_ancestors" {
                    for access in [
                        "SEARCH versions USING PRIMARY KEY (workspace_id=? AND lang=? AND generation=? AND crate_key=? AND valid_from<?)",
                        "SEARCH dependencies USING PRIMARY KEY (topology_id=?)",
                        "SEARCH origin USING PRIMARY KEY (crate_key=?)",
                        "SEARCH pending USING PRIMARY KEY (crate_key=?)",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(access)),
                            "{state:?} {} must use {access}: {plan:?}",
                            pin.name
                        );
                    }
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_derivation_sql_cr_source_imports_5" {
                    let members = plan
                        .iter()
                        .position(|row| row.contains("members"))
                        .unwrap_or_else(|| {
                            panic!("{state:?} {} has no members access: {plan:?}", pin.name)
                        });
                    let imports = plan
                        .iter()
                        .position(|row| row.contains("SEARCH target USING PRIMARY KEY (blob_id=?)"))
                        .unwrap_or_else(|| {
                            panic!("{state:?} {} has no imports access: {plan:?}", pin.name)
                        });
                    let declaration = plan
                        .iter()
                        .position(|row| row.contains("SEARCH declaration USING PRIMARY KEY"))
                        .unwrap_or_else(|| {
                            panic!("{state:?} {} has no declaration access: {plan:?}", pin.name)
                        });
                    assert!(
                        members < imports && imports < declaration,
                        "{state:?} {} must drive members, then imports, then declarations: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_derivation_sql_cr_members_2" {
                    let parent = plan
                        .iter()
                        .position(|row| row.contains("parent"))
                        .unwrap_or_else(|| {
                            panic!(
                                "{state:?} {} has no per-crate parent lookup: {plan:?}",
                                pin.name
                            )
                        });
                    let declaration = plan
                        .iter()
                        .position(|row| row.contains("declaration"))
                        .unwrap_or_else(|| {
                            panic!("{state:?} {} has no declaration lookup: {plan:?}", pin.name)
                        });
                    assert!(
                        parent < declaration,
                        "{state:?} {} must read per-crate parents before workspace declarations: {plan:?}",
                        pin.name
                    );
                    assert!(
                        plan[declaration].contains("SEARCH declaration USING PRIMARY KEY"),
                        "{state:?} {} must seek workspace declarations by blob: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_derivation_sql_cr_exports_4" {
                    let exports = plan
                        .iter()
                        .position(|row| row.contains("exports"))
                        .unwrap_or_else(|| {
                            panic!(
                                "{state:?} {} has no per-crate exports access: {plan:?}",
                                pin.name
                            )
                        });
                    let site = plan
                        .iter()
                        .position(|row| row.contains("site"))
                        .unwrap_or_else(|| {
                            panic!(
                                "{state:?} {} has no semantic-site access: {plan:?}",
                                pin.name
                            )
                        });
                    let additional = plan
                        .iter()
                        .position(|row| row.contains("additional"))
                        .unwrap_or_else(|| {
                            panic!("{state:?} {} has no namespace access: {plan:?}", pin.name)
                        });
                    assert!(
                        exports < site && site < additional,
                        "{state:?} {} must drive from per-crate exports, then semantic sites, then namespaces: {plan:?}",
                        pin.name
                    );
                    assert!(
                        plan[site].contains("SEARCH site USING PRIMARY KEY")
                            && plan[additional].contains("SEARCH additional USING PRIMARY KEY"),
                        "{state:?} {} must seek workspace semantic facts by their keys: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_source_declarations" {
                    for index in [
                        "SEARCH declaration USING PRIMARY KEY",
                        "SEARCH member USING COVERING INDEX cr_members_blob",
                        "SEARCH inner_module USING COVERING INDEX cr_scopes_range",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(index)),
                            "{state:?} {} must use {index}: {plan:?}",
                            pin.name
                        );
                    }
                    for forbidden in ["SCAN declaration", "AUTOMATIC", "CO-ROUTINE", "TEMP B-TREE"]
                    {
                        assert!(
                            !plan.iter().any(|row| row.contains(forbidden)),
                            "{state:?} {} must not use {forbidden}: {plan:?}",
                            pin.name
                        );
                    }
                }
                if pin.name == "rust_crate_derivation_sql_cr_imports_8" {
                    for seek in [
                        "SEARCH original USING PRIMARY KEY",
                        "SEARCH target USING COVERING INDEX cr_binding_targets_name (owner=? AND name=?)",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(seek)),
                            "{state:?} {} must seek canonical owner bindings at {seek}: {plan:?}",
                            pin.name
                        );
                    }
                    assert!(
                        !plan.iter().any(|row| row.contains("SCAN target")),
                        "{state:?} {} must not scan canonical bindings: {plan:?}",
                        pin.name
                    );
                }
                // Ending an open version row runs once per crate a reconcile
                // re-derives, which is every crate in a derivation-version
                // rotation, so it seeks that crate's rows by key.
                if matches!(
                    pin.name.as_str(),
                    "rust_crate_reconcile_sql_rust_crate_versions_16"
                        | "rust_crate_reconcile_sql_rust_crate_versions_withdraw"
                ) {
                    assert!(
                        plan.iter().any(|row| {
                            row.contains("SEARCH rust_crate_versions USING PRIMARY KEY")
                        }),
                        "{state:?} {} must seek the crate's version rows by key: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_replaced_blob_id" {
                    for index in [
                        "rust_crate_containers_blob",
                        "rust_crate_exports_declaration",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(index)),
                            "{state:?}: {plan:?}"
                        );
                    }
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?}: {plan:?}"
                    );
                }
                // A root reference's module anchor is a key seek. Scanning the
                // anchors per reference cost 61 s of a 78 s derivation of the
                // analysis crate (#3749).
                if pin.name == "rust_crate_root_references_select" {
                    assert!(
                        plan.iter()
                            .any(|row| row.contains("SEARCH anchor USING PRIMARY KEY")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan
                            .iter()
                            .any(|row| row.contains("SCAN anchor") || row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
                // Every working statement of the trait-implementation
                // derivation seeks: the tier-1 family by its primary key, the
                // module route by its key, the export the half binds by the
                // complete export key, and the binding the gap statement tests
                // for by its key. The insert and the row select are the only
                // two that are not joins, as they are for every other family.
                if let Some(index) = match pin.name.as_str() {
                    "rust_crate_trait_impl_sources" | "rust_crate_trait_impl_rows" => {
                        Some("SEARCH subject USING PRIMARY KEY")
                    }
                    "rust_crate_root_routes"
                    | "rust_crate_trait_impl_subject_routes"
                    | "rust_crate_trait_impl_trait_routes" => Some("SEARCH path USING PRIMARY KEY"),
                    "rust_crate_trait_impl_subject_bindings"
                    | "rust_crate_trait_impl_trait_bindings" => Some("SEARCH target USING"),
                    "rust_crate_trait_impl_subject_glob_bindings"
                    | "rust_crate_trait_impl_trait_glob_bindings" => {
                        Some("SEARCH exports USING PRIMARY KEY")
                    }
                    "rust_crate_trait_impl_subject_gaps" | "rust_crate_trait_impl_trait_gaps" => {
                        Some("SEARCH declaration USING PRIMARY KEY")
                    }
                    "rust_crate_trait_impl_declarations" => {
                        Some("SEARCH exports USING PRIMARY KEY")
                    }
                    _ => None,
                } {
                    assert!(
                        plan.iter().any(|row| row.contains(index)),
                        "{state:?} {} must use {index}: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
                if matches!(
                    pin.name.as_str(),
                    "rust_crate_source_declarations"
                        | "rust_crate_export_declarations"
                        | "rust_crate_enum_containers"
                        | "rust_crate_enum_variants"
                        | "rust_crate_export_fixpoint"
                        | "rust_crate_export_source_edges"
                        | "rust_crate_import_routes"
                        | "rust_crate_derivation_sql_cr_imports_8"
                        | "rust_crate_macro_items"
                ) {
                    eprintln!("{state:?} {}: {plan:?}", pin.name);
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    let index = match pin.name.as_str() {
                        "rust_crate_source_declarations" => "SEARCH declaration USING PRIMARY KEY",
                        "rust_crate_export_declarations" => "SEARCH bridges USING",
                        "rust_crate_enum_containers" => "SEARCH bridge USING",
                        "rust_crate_enum_variants" => {
                            "SEARCH candidate USING INDEX cr_source_declarations_declaration"
                        }
                        "rust_crate_export_source_edges" => "SEARCH route USING PRIMARY KEY",
                        "rust_crate_export_fixpoint" => {
                            "SEARCH lookup USING COVERING INDEX cr_binding_lookups_target"
                        }
                        "rust_crate_import_routes" => "SEARCH path USING PRIMARY KEY",
                        "rust_crate_derivation_sql_cr_imports_8" => {
                            "SEARCH target USING COVERING INDEX cr_binding_targets_name"
                        }
                        "rust_crate_macro_items" => "SEARCH properties USING PRIMARY KEY",
                        _ => "SEARCH exports USING PRIMARY KEY",
                    };
                    // Both export-source join orders are indexed: the
                    // multi-target route key can make routes the cheaper
                    // driver, with a full-key seek into source imports.
                    assert!(
                        plan.iter().any(|row| {
                            row.contains(index)
                                || (pin.name == "rust_crate_export_source_edges"
                                    && row.contains("SEARCH source USING PRIMARY KEY (blob_id=? AND import_ordinal=? AND module_path=?)"))
                        }),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon(
        "#4994: a projection drop pruned content-addressed summaries the next build re-derived"
    )]
    fn projection_drop_retains_summaries_for_rebinding_until_gc() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"retained\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub struct Export;\npub fn make() -> Export { Export }\n",
            )
            .with_git()
            .build();
        let build = || {
            WorkspaceAnalyzer::build_scoped_persisted(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .unwrap()
        };
        let first = build();
        let db_path = first.persisted_store_path().unwrap();
        let summaries = |store: &AnalyzerStore| -> Vec<(i64, Vec<u8>)> {
            store.read_conn().unwrap()
                .prepare("SELECT summary_id, summary_digest FROM resolution_unit_summaries ORDER BY summary_id")
                .unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap().collect::<rusqlite::Result<_>>().unwrap()
        };
        let original = summaries(first.store().unwrap().as_ref());
        assert!(!original.is_empty());
        drop(first); // The scoped workspace's final owner drops its projection lease.
        let store = AnalyzerStore::open_persistent(&db_path).unwrap();
        assert_eq!(summaries(&store), original);
        assert_eq!(
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM resolution_unit_summary_versions",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .read_conn_for_workspace(&Default::default())
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM selected_rust_unit_summaries",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "retained unbound headers are invisible to readers"
        );

        let second = build();
        assert_eq!(
            summaries(second.store().unwrap().as_ref()),
            original,
            "identical inputs must bind the retained headers without inserting new ones"
        );
        let conn = second.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM resolution_unit_summary_versions",
                [],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
            original.len()
        );
        drop(conn);
        store.reclaim_stale_generations(1).unwrap();
        assert_eq!(summaries(&store), original, "GC preserves bound summaries");
        drop(second);
        store.reclaim_stale_generations(1).unwrap();
        assert!(
            summaries(&store).is_empty(),
            "GC sweeps orphans without stale generations"
        );
        assert_eq!(
            store
                .read_conn()
                .unwrap()
                .query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            0
        );
        // A completed scheduled collection must sweep the same orphans too;
        // before #4994 only forced collection called stale-generation reclaim.
        let third = build();
        drop(third);
        assert!(!summaries(&store).is_empty());
        let _tuning = brokk_bifrost_core::cache_gc::set_tuning_for_test(0, 0);
        let repository = git2::Repository::open(project.root()).unwrap();
        let outcome = brokk_bifrost_analysis::cache_gc::maybe_gc_for_analyzer(
            &store,
            &repository,
            project.root(),
        )
        .unwrap();
        assert!(outcome.ran, "the periodic collection must run: {outcome:?}");
        assert!(
            summaries(&store).is_empty(),
            "periodic GC must sweep retained summaries"
        );
        assert_eq!(
            store
                .read_conn()
                .unwrap()
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn crate_rows_release_foreign_keys_on_workspace_retirement_and_epoch_rotation() {
        let project = fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let workspace = {
            let conn = store.read_conn().unwrap();
            let id: String = conn
                .query_row(
                    "SELECT workspace_id FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            brokk_bifrost_analysis::analyzer::store::WorkspaceId(id)
        };
        assert!(store.delete_workspace_projection(&workspace).unwrap() > 0);
        assert!(
            store
                .read_conn()
                .unwrap()
                .query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap()
                > 0,
            "projection retirement retains reusable topologies until GC"
        );
        store.reclaim_stale_generations(1).unwrap();
        let conn = store.read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        drop(conn);
        let project = fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        store
            .ensure_language_epoch_value("rust", "crate-row-lifecycle-test")
            .unwrap();
        let conn = store.read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_versions", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    #[test]
    #[hardwon("20974f2e7d10: distinct named re-export aliases were collapsed for one target")]
    fn crate_glob_reexports_reach_dependency_names_through_selected_rows() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n")
            .file("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n")
            .file("dep/Cargo.toml", "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
            .file("app/src/lib.rs", "pub use dep::*; pub use dep::X as Y; pub use dep::X as Z;")
            .file("dep/src/lib.rs", "pub struct X; fn private() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn_for_workspace(&Default::default()).unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let id: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='app'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_reexport_routes WHERE topology_id=?1 AND bound_name='Y' AND target_name='X'", [id], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_glob_reexport_routes WHERE topology_id=?1 AND module_path='crate' AND target_module_path='crate'", [id], |row| row.get::<_, i64>(0)).unwrap(), 1);
        let names = conn.prepare("SELECT namespace || ':' || name FROM rust_crate_exports_reachable WHERE topology_id=?1 ORDER BY 1").unwrap().query_map([id], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            names,
            [
                "type:X", "type:Y", "type:Z", "value:X", "value:Y", "value:Z"
            ]
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    // A glob binds names the walk must follow, and a glob's own path can be
    // one of those names, so routes and globs are one fixpoint. `Target` needs
    // the glob edges a first pass discovers; `Deeper` needs the edge that
    // `use leaf::*;` only becomes once `leaf` itself has a route, so it proves
    // the loop runs again rather than closing the edges it already had.
    #[test]
    #[hardwon("#2130: chained glob imports were absent from reverse route discovery")]
    fn crate_import_routes_follow_a_chain_of_glob_imports() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"chained\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", "mod consumer;\npub mod a;\npub use a::*;\n")
            .file("src/a.rs", "pub mod b;\npub use b::*;\n")
            .file(
                "src/a/b.rs",
                "pub mod leaf { pub struct Target; pub mod deep { pub struct Deeper; } }\n",
            )
            .file(
                "src/consumer.rs",
                "use crate::*;\nuse leaf::Target;\nuse leaf::*;\nuse deep::Deeper;\n\nfn consume(_: Target, _: Deeper) {}\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let id: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='chained'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let routed = conn
            .prepare(
                "SELECT DISTINCT bound_name || ' -> ' || target_module_path || '::' || target_name
                 FROM rust_crate_imports
                 WHERE topology_id=?1 AND module_path='crate::consumer' ORDER BY 1",
            )
            .unwrap()
            .query_map([id], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            routed,
            [
                "Deeper -> crate::a::b::leaf::deep::Deeper",
                "Target -> crate::a::b::leaf::Target",
            ]
        );
    }

    #[test]
    #[hardwon("ee1b607d617b: restricted visibility must follow canonical module routes")]
    fn crate_restricted_visibility_resolves_module_routes_and_gaps() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='visibility'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "src/lib.rs",
                r#"
mod outer {
    mod inner {
        pub(self) struct Here;
        pub(super) struct Parent;
        pub(in crate::outer) struct Absolute;
        pub(in super) struct Relative;
        pub(in self) struct Same;
        pub(in super::super) struct Root;
        pub(in crate::absent) struct Missing;
        pub(in super) use self::Parent as Alias;
    }
}
"#,
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        let rows = conn.prepare("SELECT name, restricted_module_path FROM rust_crate_exports WHERE namespace='type' AND module_path='crate::outer::inner' ORDER BY name").unwrap()
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            rows,
            [
                ("Absolute".into(), "crate::outer".into()),
                ("Alias".into(), "crate::outer".into()),
                ("Here".into(), "crate::outer::inner".into()),
                ("Parent".into(), "crate::outer".into()),
                ("Relative".into(), "crate::outer".into()),
                ("Root".into(), "crate".into()),
                ("Same".into(), "crate::outer::inner".into()),
            ]
        );
        let gaps: i64 = conn.query_row("SELECT count(*) FROM rust_crate_gaps WHERE gap_kind='unresolved_visibility' AND subject='crate::outer::inner'", [], |row| row.get(0)).unwrap();
        assert_eq!(gaps, 1);
    }

    #[test]
    fn crate_point_rows_distinguish_open_and_closed_export_inventories() {
        let mut evidence = Vec::new();
        // The fourth and fifth cases write the second case's invocation under
        // a `macro_rules!` the root makes visible in the mounted file. A proven
        // item passthrough with no arguments decides it and declares nothing,
        // so the module's inventory closes. A visible definition the matcher
        // did not prove to be a passthrough decides nothing, and this one does
        // declare an item of its own, so the inventory stays open exactly as it
        // does for the second case, whose macro is visible nowhere. Reading
        // "not proven a passthrough" as "adds no items" closed it on no proof
        // at all.
        //
        // The later cases give a proven passthrough an item. Declared in the
        // same file with rules that expand to their arguments only, the
        // producer declares the item, it is exported, and the inventory
        // closes. Every other decided invocation's items are the crate's to
        // declare (`rust_crate_macro_items`, which the point and graph routes
        // read): a macro declared in another file, and rules that add a `cfg`
        // to each item, whose activation the crate evaluates. Their inventory
        // closes once every item is accounted for. A unit struct is declared
        // in both namespaces. A decoration the profile turns off declares
        // nothing and still closes the inventory: the item is absent. An
        // invocation in an `impl` body expands to members, not module items,
        // so it declares no row and closes too. A rule that adds an attribute
        // other than a `cfg` leaves the invocation undecided and open.
        let passthrough = "macro_rules! generate { ($($item:item)*) => { $($item)* }; }\n";
        let decorating =
            "macro_rules! generate { ($($item:item)*) => { $(#[cfg(unix)] $item)* }; }\n";
        let opaque_decoration =
            "macro_rules! generate { ($($item:item)*) => { $(#[allow(dead_code)] $item)* }; }\n";
        let local_passthrough = format!("{passthrough}generate! {{ pub struct Extra; }}\n");
        let extra_in = |module: &str| {
            let module = module.to_owned();
            ["type", "value"]
                .map(|namespace| {
                    (
                        module.clone(),
                        namespace.to_owned(),
                        "Extra".to_owned(),
                        "public".to_owned(),
                        false,
                    )
                })
                .to_vec()
        };
        let extra = || extra_in("crate::provider");
        for (root_macro, provider, open, decided, exported, crate_declared) in [
            ("", "", false, false, false, Vec::new()),
            ("", "generate!();\n", true, false, false, Vec::new()),
            (
                "",
                "fn local() { generate!(); }\n",
                false,
                false,
                false,
                Vec::new(),
            ),
            (
                passthrough,
                "generate!();\n",
                false,
                false,
                false,
                Vec::new(),
            ),
            (
                "macro_rules! generate { () => { pub struct Extra; }; }\n",
                "generate!();\n",
                true,
                false,
                false,
                Vec::new(),
            ),
            (
                passthrough,
                "generate! { pub struct Extra; }\n",
                false,
                false,
                false,
                extra(),
            ),
            (
                decorating,
                "generate! { pub struct Extra; }\n",
                false,
                false,
                false,
                if cfg!(unix) { extra() } else { Vec::new() },
            ),
            (
                opaque_decoration,
                "generate! { pub struct Extra; }\n",
                true,
                false,
                false,
                Vec::new(),
            ),
            (
                passthrough,
                "pub struct Holder;\nimpl Holder { generate! { pub const Extra: u8 = 0; } }\n",
                false,
                false,
                false,
                Vec::new(),
            ),
            (
                "",
                local_passthrough.as_str(),
                false,
                false,
                true,
                Vec::new(),
            ),
            (
                passthrough,
                "pub mod inner { generate! { pub struct Extra; } }\n",
                false,
                false,
                false,
                extra_in("crate::provider::inner"),
            ),
        ] {
            let project = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[package]\nname='inventory'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file(
                    "src/lib.rs",
                    format!("{root_macro}pub mod provider;\nuse crate::provider::Target;\n"),
                )
                .file("src/provider.rs", provider)
                .build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn_for_workspace(&Default::default()).unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            let topology: i64 = conn
                .query_row(
                    "SELECT topology_id FROM selected_rust_crates WHERE crate_name='inventory'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let gaps = conn.prepare("SELECT gap_kind,subject,json(detail) FROM rust_crate_gaps WHERE topology_id=?1 ORDER BY gap_kind,subject").unwrap().query_map([topology], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let names = conn.prepare("SELECT module_path,namespace,name FROM rust_crate_exports WHERE topology_id=?1 ORDER BY module_path,namespace,name").unwrap().query_map([topology], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let macro_count: i64 = conn.query_row("SELECT count(*) FROM rust_crate_container_sources AS source CROSS JOIN source_rust_macro_invocations AS invocation ON invocation.blob_id=source.blob_id WHERE source.topology_id=?1 AND source.container_path='crate::provider'", [topology], |row| row.get(0)).unwrap();
            eprintln!(
                "provider={provider:?}, macro_count={macro_count}, exports={names:?}, gaps={gaps:?}"
            );
            assert_eq!(macro_count, i64::from(provider.contains("generate!")));
            let inventory = gaps.iter().find(|(kind, subject, _)| {
                kind == "open_export_inventory" && subject == "crate::provider"
            });
            assert_eq!(
                inventory.is_some(),
                open,
                "item position controls export inventory: {gaps:?}"
            );
            if let Some((_, _, detail)) = inventory {
                let detail: serde_json::Value = serde_json::from_str(detail).unwrap();
                let evidence = &detail["evidence"][0];
                assert!(evidence["member_blob"].is_i64());
                assert!(evidence["invocation_occurrence"].is_u64());
                assert_eq!(evidence["replay_covered"], false);
                assert_eq!(evidence["reason"], "UnsupportedMacroGeneratedModule");
                assert_eq!(evidence["decided"], decided, "{gaps:?}");
            }
            // Only an item the file's producer declared is a persisted export.
            let persisted = names
                .iter()
                .any(|(module, _, name)| module == "crate::provider" && name == "Extra");
            assert_eq!(persisted, exported, "{names:?}");
            let declared = conn.prepare("SELECT module_path,namespace,name,visibility,module_item FROM rust_crate_macro_items WHERE topology_id=?1 ORDER BY module_path,namespace,name").unwrap().query_map([topology], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,bool>(4)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(declared, crate_declared, "{root_macro:?} {provider:?}");
            evidence.push((names, gaps));
        }
        assert_ne!(
            evidence[0], evidence[1],
            "the row consumer needs an open-export-inventory gap; absent Target is a proved negative only for the closed module"
        );
    }

    #[test]
    #[hardwon("#2767: identical blobs at different placements need distinct crate file identities")]
    fn crate_file_naming_keeps_same_blob_placements_and_bench_identity() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='identity'\nversion='0.1.0'\nedition='2024'\n[[bench]]\nname='custom_target'\npath='benches/routes.rs'\nharness=false\n")
            .file("src/lib.rs", "pub mod a; pub mod b;")
            .file("src/a.rs", "pub fn target() {}")
            .file("src/b.rs", "pub fn target() {}")
            .file("benches/routes.rs", "#[path=\"common/mod.rs\"] mod shared;")
            .file("benches/common/mod.rs", "pub fn target() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let mut names = conn.prepare("SELECT DISTINCT rel_path,json(package_components) FROM rust_crate_file_naming ORDER BY rel_path").unwrap();
        let actual = names
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            actual,
            [
                (
                    "benches/common/mod.rs".to_owned(),
                    r#"["identity","benches","common"]"#.to_owned()
                ),
                (
                    "benches/routes.rs".to_owned(),
                    r#"["identity","benches","routes"]"#.to_owned()
                ),
                ("src/a.rs".to_owned(), r#"["identity","a"]"#.to_owned()),
                ("src/b.rs".to_owned(), r#"["identity","b"]"#.to_owned()),
                ("src/lib.rs".to_owned(), r#"["identity"]"#.to_owned()),
            ]
        );
    }

    #[test]
    #[hardwon("285dc95915fc: inline module keys used the wrong source identity")]
    fn crate_inline_module_keys_use_declaration_names() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='inline'\nversion='0.1.0'\nedition='2024'\n")
            .file("src/lib.rs", "pub mod provider { pub mod model { pub fn Target() {} } pub use model::Target; }\nuse crate::provider::Target as Alias;\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let paths = conn
            .prepare("SELECT container_path FROM rust_crate_containers ORDER BY container_path")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            paths,
            ["crate", "crate::provider", "crate::provider::model"]
        );
        let count: i64 = conn.query_row("SELECT count(*) FROM rust_crate_exports WHERE module_path='crate::provider' AND name='Target' AND namespace='value'", [], |row|row.get(0)).unwrap();
        assert_eq!(
            count, 1,
            "the parent's reexport must reach the nested declaration"
        );
    }

    #[test]
    #[hardwon("dea5c8db472c: dependency re-exports were missing point binder rows")]
    fn crate_point_binder_rows_follow_dependency_named_reexports() {
        for (facade_source, imported_name) in [
            ("pub use dep::Thing as Public;", "Public"),
            ("pub use dep::*;", "Thing"),
            ("pub use bridge::Public as Renamed;", "Renamed"),
            ("pub use bridge::*;", "Public"),
        ] {
            let project = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=[\"app\",\"facade\",\"bridge\",\"dep\"]\nresolver=\"2\"\n")
            .file("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nfacade={path=\"../facade\"}\n")
            .file("facade/Cargo.toml", "[package]\nname=\"facade\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\nbridge={path=\"../bridge\"}\n")
            .file("dep/Cargo.toml", "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
            .file("bridge/Cargo.toml", "[package]\nname=\"bridge\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n")
            .file("bridge/src/lib.rs", "pub use dep::Thing as Public;")
            .file("app/src/lib.rs", format!("use facade::{imported_name} as Local; pub fn make() -> Local {{ Local }}"))
            .file("facade/src/lib.rs", facade_source)
            .file("dep/src/lib.rs", "pub struct Thing;")
            .build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.read_conn_for_workspace(&Default::default()).unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            let facade: i64 = conn
                .query_row(
                    "SELECT topology_id FROM selected_rust_crates WHERE crate_name='facade'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let app: i64 = conn
                .query_row(
                    "SELECT topology_id FROM selected_rust_crates WHERE crate_name='app'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let source_imports = conn.prepare("SELECT imports.bound_name, imports.imported_name, imports.native_scope FROM selected_rust_crate_containers AS modules JOIN source_rust_import_targets AS imports ON imports.blob_id = modules.blob_id WHERE modules.topology_id = ?1").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u32>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                source_imports,
                [("Local".into(), imported_name.into(), 0)],
                "the producer has the structured source binder"
            );
            let exports = conn.prepare("SELECT namespace FROM rust_crate_exports_reachable WHERE topology_id=?1 AND module_path='crate' AND name=?2 ORDER BY namespace").unwrap().query_map(params![facade, imported_name], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                exports,
                ["type", "value"],
                "the dependency exposes both namespaces"
            );
            let bindings = conn.prepare("SELECT namespace, bound_name, target_module_path, target_name FROM rust_crate_imports WHERE topology_id=?1 ORDER BY namespace").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let gaps = conn.prepare("SELECT gap_kind, subject, json(detail) FROM rust_crate_gaps WHERE topology_id=?1 ORDER BY gap_kind, subject").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                bindings,
                [
                    (
                        "type".into(),
                        "Local".into(),
                        "crate".into(),
                        "Thing".into()
                    ),
                    (
                        "value".into(),
                        "Local".into(),
                        "crate".into(),
                        "Thing".into()
                    ),
                ],
                "a point route must find persisted binder authority; gaps={gaps:?}"
            );
            assert!(
                gaps.is_empty(),
                "a resolved reexport is not an import gap: {gaps:?}"
            );
        }
    }

    #[test]
    #[hardwon("#5658: integer native namespaces published local types only as values")]
    fn local_authority_namespace_codes_preserve_type_and_value_bindings() {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname=\"local_namespace\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[workspace]\n")
            .file("src/lib.rs", "fn probe() { struct Local; let _: Local = Local; }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        for namespace in [ResolutionNamespace::Type, ResolutionNamespace::Value] {
            let native_code =
                brokk_bifrost_analysis::analyzer::store::resolution_prepare::reference_lookup_namespace_codes(namespace)[0];
            let rows = conn.prepare("SELECT owner.closed, certificate.complete, alternative.declaration_site=authority.source_site
 FROM rust_crate_binding_owners owner
 JOIN resolution_node_catalog scope ON scope.blob_id=owner.blob_id AND scope.source_scope=owner.native_scope
 JOIN resolution_paths path ON path.blob_id=scope.blob_id AND path.start_node=scope.local_key
 JOIN resolution_identities name ON name.id=path.start_lead_identity AND name.namespace=?1 AND name.spelling='Local'
 JOIN resolution_node_catalog endpoint ON endpoint.blob_id=path.blob_id AND endpoint.local_key=path.end_node
 JOIN resolution_rust_declaration_authorities authority ON authority.blob_id=endpoint.blob_id AND authority.semantic_key=endpoint.semantic_local_key
 LEFT JOIN rust_crate_binding_names certificate ON certificate.owner_id=owner.owner_id AND certificate.namespace=?2 AND certificate.name=name.spelling
 LEFT JOIN rust_crate_binding_alternatives alternative ON alternative.owner_id=certificate.owner_id AND alternative.namespace=certificate.namespace AND alternative.name=certificate.name AND alternative.declaration_blob_id=authority.blob_id
 WHERE owner.kind='local' AND path.root_terminal IS NULL AND path.end_lead_identity IS NULL AND path.end_lead_local IS NULL")
                .unwrap().query_map(params![native_code, namespace.label()], |row| Ok((row.get::<_,bool>(0)?,row.get::<_,Option<bool>>(1)?,row.get::<_,Option<bool>>(2)?)))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(
                rows,
                [(true, Some(true), Some(true))],
                "native and published {namespace:?} authority must agree"
            );
        }
    }

    #[test]
    #[hardwon("#5658: an owner's unsupported item macro left its bound names certified complete")]
    fn owner_gap_voids_published_binding_certificates() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"owner_gap\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[workspace]\n",
            )
            .file(
                "src/lib.rs",
                "macro_rules! make { () => { pub mod x { pub struct T; } }; }\n\
                 pub mod a { pub mod x { pub struct T; } }\n\
                 pub use a::*;\nmake!();\npub use x::T;\npub fn probe() {}\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT certificate.namespace, certificate.name, certificate.complete,
                        EXISTS(SELECT 1 FROM rust_crate_binding_blockers blocker
                               WHERE blocker.owner_id=owner.owner_id AND blocker.namespace=certificate.namespace
                                 AND blocker.name='' AND blocker.reason='UnsupportedMacroGeneratedModule')
                 FROM rust_crate_binding_owners owner
                 JOIN rust_crate_binding_names certificate USING(owner_id)
                 WHERE owner.module_path='crate' AND owner.kind='module'
                   AND (certificate.namespace, certificate.name) IN
                       (VALUES ('macro','make'), ('type','a'), ('value','probe'))
                 ORDER BY 1, 2",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                ("macro".to_owned(), "make".to_owned(), false, true),
                ("type".to_owned(), "a".to_owned(), false, true),
                ("value".to_owned(), "probe".to_owned(), false, true),
            ]
        );
    }

    #[test]
    #[hardwon(
        "#5658: a private glob's conflict evidence reached a module that cannot import the name"
    )]
    fn glob_blockers_follow_importable_bindings() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname=\"glob_blockers\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[workspace]\n")
            .file(
                "src/lib.rs",
                "mod a { pub struct T; }\nmod b { pub struct T; }\n\
                 mod private_first { use crate::a::*; pub use crate::b::*; }\n\
                 mod visible { pub struct T; }\n\
                 mod lone { use crate::private_first::*; pub fn probe(_: T) {} }\n\
                 mod downstream { use crate::lone::*; use crate::visible::*; pub fn probe(_: T) {} }\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        // lone binds T only through a private glob, so downstream sees just
        // visible::T and none of lone's conflict evidence.
        let rows = conn
            .prepare(
                "SELECT owner.module_path, blocker.reason FROM rust_crate_binding_owners owner
                 JOIN rust_crate_binding_blockers blocker USING(owner_id)
                 WHERE owner.module_path IN ('crate::lone', 'crate::downstream')
                   AND blocker.namespace='type' AND blocker.name='T' ORDER BY 1, 2",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            rows.iter().all(|(module, _)| module == "crate::lone") && !rows.is_empty(),
            "only lone carries T's conflict evidence: {rows:?}"
        );
    }

    #[test]
    #[hardwon(
        "#5658: P3 differential found an extern-prelude crate-root alias with no published alternative"
    )]
    fn prelude_root_aliases_publish_certified_named_import_witnesses() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname=\"prelude_root\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[workspace]\n[dependencies]\ndep={path=\"dep\"}\n")
            .file("dep/Cargo.toml", "[package]\nname=\"dep\"\nversion=\"0.0.0\"\nedition=\"2021\"\n")
            .file("dep/src/lib.rs", "pub struct T;\n")
            .file(
                "src/lib.rs",
                "mod local { pub fn dep() {} }\nuse local::*;\nuse dep as chosen;\n\
                 mod a { pub struct T; }\nmod b { pub struct T; }\n\
                 mod private_first { use crate::a::*; pub use crate::b::*; }\n\
                 mod named { use crate::private_first::T as Alias; }\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let alternatives = |module: &str, name: &str| -> Vec<(String, String, String, bool)> {
            conn.prepare(
                "SELECT alternative.target_module_path, alternative.target_name, alternative.origin,
                        alternative.target_crate_key=topology.crate_key
                 FROM rust_crate_binding_owners owner
                 JOIN rust_crate_topologies topology USING(topology_id)
                 JOIN rust_crate_binding_alternatives alternative USING(owner_id)
                 WHERE owner.module_path=?1 AND owner.kind='module'
                   AND alternative.namespace='type' AND alternative.name=?2
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map(params![module, name], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };
        // The alias binds the dependency's root; the glob's `dep` is a value.
        assert_eq!(
            alternatives("crate", "chosen"),
            [(
                "crate".to_owned(),
                "self".to_owned(),
                "named_import".to_owned(),
                false
            )]
        );
        // A named import of a partial mixed-visibility glob group stays uncertified.
        assert_eq!(alternatives("crate::named", "Alias"), []);
    }

    /// Every live crate row, with each store-local surrogate replaced by the
    /// content it stands for, so that two independently built stores compare
    /// equal exactly when they publish the same crates.
    ///
    /// A topology id becomes the digest of the topology an open version row
    /// binds, and a column whose foreign key names a blob becomes that blob's
    /// OID. A version row keeps its crate, topology and manifest, but not its
    /// workspace coordinates or revision, which count within one store. Tables
    /// and columns come from the schema, so a crate table added later is
    /// compared without editing this.
    fn live_crate_rows(conn: &Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
        let rows = |sql: &str| -> Vec<Vec<rusqlite::types::Value>> {
            let mut statement = conn.prepare(sql).unwrap();
            let width = statement.column_count();
            statement
                .query_map([], |row| (0..width).map(|index| row.get(index)).collect())
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let names = |sql: &str, table: &str| -> Vec<String> {
            conn.prepare(sql)
                .unwrap()
                .query_map([table], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let mut live = vec![(
            "rust_crate_versions".to_owned(),
            rows("SELECT versions.crate_key, topologies.topology_digest, manifest.rel_path, manifest.blob_oid
                  FROM rust_crate_versions AS versions
                  JOIN rust_crate_topologies AS topologies USING(topology_id)
                  LEFT JOIN workspace_file_versions AS manifest
                    ON manifest.file_version_id = versions.manifest_file_version_id
                  WHERE versions.valid_until IS NULL ORDER BY 1"),
        )];
        let tables = names(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name GLOB 'rust_crate_*' AND name <> ?1
               AND name <> 'rust_crate_reconciliations' ORDER BY name",
            "rust_crate_versions",
        );
        for table in tables {
            let columns = names(
                "SELECT name FROM pragma_table_info(?1) ORDER BY cid",
                &table,
            );
            let blob_columns = names(
                "SELECT \"from\" FROM pragma_foreign_key_list(?1) WHERE \"table\" IN ('blobs', 'resolution_fragment_interiors')",
                &table,
            );
            let owner_keyed = !columns.iter().any(|column| column == "topology_id");
            assert!(
                !owner_keyed || columns.iter().any(|column| column == "owner_id"),
                "{table} is keyed by topology or its owner: {columns:?}"
            );
            let select = columns
                .iter()
                .filter(|column| column.as_str() != "alternative_id")
                .map(|column| {
                    if column == "topology_id" {
                        "live.topology_digest".to_owned()
                    } else if column == "owner_id" || column == "parent_owner_id" {
                        format!("(SELECT json_array(owner.module_path,owner.kind,owner.rel_path,hex(owner.scope_identity)) FROM rust_crate_binding_owners owner WHERE owner.owner_id=row.{column})")
                    } else if column == "mount_blob_id" {
                        // mount_blob_id uses -1 for a synthetic mount and has
                        // no FK, but positive values are store-local blob ids.
                        format!("CASE WHEN row.{column} = -1 THEN -1 ELSE (SELECT blob_oid FROM blobs WHERE id = row.{column}) END")
                    } else if blob_columns.contains(column) {
                        format!("(SELECT blob_oid FROM blobs WHERE id = row.{column})")
                    } else {
                        format!("row.{column}")
                    }
                })
                .collect::<Vec<_>>();
            let order = (1..=select.len())
                .map(|position| position.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let owner_join = if owner_keyed {
                "JOIN rust_crate_binding_owners AS authority_owner ON authority_owner.owner_id=row.owner_id"
            } else {
                ""
            };
            let topology = if owner_keyed {
                "authority_owner.topology_id"
            } else {
                "row.topology_id"
            };
            let table_rows = rows(&format!(
                "SELECT {} FROM {table} AS row {owner_join}
                 JOIN (SELECT topology_id, topology_digest FROM rust_crate_versions
                       JOIN rust_crate_topologies USING(topology_id)
                       WHERE valid_until IS NULL) AS live ON live.topology_id={topology}
                 ORDER BY {order}",
                select.join(", ")
            ));
            live.push((table, table_rows));
        }
        live
    }

    /// A derivation-version rotation on a warm store, which is what a release
    /// upgrade does: no file changed, so the build opens no revision, and every
    /// crate's topology digest moves because it folds in the version.
    ///
    /// The publish path used to close the open version row at the revision it
    /// was about to reopen it at, and `rust_crate_versions` rejects an interval
    /// that ends where it starts. Pipeline two found it against a real tract
    /// cache, one second into the upgrade, as eight
    /// `CHECK constraint failed: valid_until IS NULL OR valid_until > valid_from`
    /// errors inside the derivation wave. No test had rotated the version
    /// without first deleting the version rows.
    ///
    /// The store is persisted and rebuilt the way the upgrade rebuilds it. An
    /// edit between the first two builds leaves one crate opened at the current
    /// revision and the rest at the first, so the rotation ends open rows both
    /// ways: it withdraws the rows this revision opened and closes the older
    /// ones. The oracle is a from-scratch build under the new version, whose
    /// live rows the rotated store must reproduce.
    #[test]
    #[hardwon(
        "a48b9658c627: crate derivation changes reused stale Rust unit summaries on warm start"
    )]
    fn warm_derivation_version_rotation_replaces_same_revision_versions() {
        if run_derivation_version_child() {
            return;
        }
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        type VersionRow = (Vec<u8>, i64, Option<i64>, Vec<u8>);
        let project = fixture();
        let build =
            || WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default());
        let head = |analyzer: &WorkspaceAnalyzer| -> i64 {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let versions = |analyzer: &WorkspaceAnalyzer| -> Vec<VersionRow> {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .prepare(
                    "SELECT versions.crate_key, versions.valid_from, versions.valid_until, topologies.topology_digest
                     FROM rust_crate_versions AS versions
                     JOIN rust_crate_topologies AS topologies USING(topology_id)
                     ORDER BY 1, 2",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };

        // Seed a genuinely old summary read set through the real producer,
        // rather than changing metadata on a current summary digest.
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RustUnitSummaries;
        use brokk_bifrost_analysis::analyzer::store::unit_summaries::{
            ConsumedDependency, UnitInputs, UnitOutputs, UnitSummaryLanguage,
        };
        struct PreviousCfgSummaryReads;
        impl UnitSummaryLanguage for PreviousCfgSummaryReads {
            fn lang(&self) -> &'static str {
                "rust"
            }
            fn unit_kind(&self) -> &'static str {
                "rust_crate"
            }
            fn derivation_version(&self) -> i64 {
                RustUnitSummaries.derivation_version()
            }
            fn stage(&self, conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<()> {
                RustUnitSummaries.stage(conn, snapshot)
            }
            fn clear_stage(&self, conn: &Connection) -> Result<()> {
                RustUnitSummaries.clear_stage(conn)
            }
            fn inputs(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit_id: i64,
            ) -> Result<UnitInputs> {
                use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
                let removed = ["rust-crate-derivation", "rust-crate-topology"].map(|name| {
                    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-read-key:v1");
                    hash.field("name", name.as_bytes());
                    hash.finish()
                });
                let mut inputs = RustUnitSummaries.inputs(conn, snapshot, unit_id)?;
                inputs
                    .reads
                    .retain(|read| !removed.contains(&read.key_digest));
                Ok(inputs)
            }
            fn derive(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit: &UnitInputs,
                dependencies: &[ConsumedDependency],
                producer_epoch: &str,
            ) -> Result<UnitOutputs> {
                RustUnitSummaries.derive(conn, snapshot, unit, dependencies, producer_epoch)
            }
            fn write_language_rows(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit: &UnitInputs,
                dependencies: &[ConsumedDependency],
                summary_id: i64,
            ) -> Result<usize> {
                RustUnitSummaries.write_language_rows(
                    conn,
                    snapshot,
                    unit,
                    dependencies,
                    summary_id,
                )
            }
            fn write_language_version(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit: &UnitInputs,
                summary_id: i64,
            ) -> Result<usize> {
                RustUnitSummaries.write_language_version(conn, snapshot, unit, summary_id)
            }
        }
        let old_version = RUST_CRATE_DERIVATION_VERSION
            .split_once("-absent-feature-cfg-inactive-v1")
            .expect("the upgrade starts with the previous crate derivation version")
            .0;
        set_derivation_version(Some(old_version));
        let first = build().expect("the first build succeeds");
        let first_revision = head(&first);
        drop(first);
        project
            .file("dep/src/on.rs")
            .write("pub fn enabled() { let body = 1; let _ = body; }")
            .unwrap();
        let warm = build().expect("the edited workspace rebuilds");
        let revision = head(&warm);
        assert!(revision > first_revision, "the edit opens a revision");
        let before = versions(&warm);
        let store = warm.store().unwrap();
        let snapshot = {
            let conn = store.read_conn().unwrap();
            conn.query_row(
                "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| {
                    Ok(WorkspaceSnapshotId {
                        workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(
                            row.get(0)?,
                        ),
                        lang: "rust".into(),
                        generation:
                            brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                                row.get(1)?,
                            ),
                        revision: row.get(2)?,
                    })
                },
            )
            .unwrap()
        };
        store
            .conn
            .execute_fixture(|conn| {
                conn.execute_batch(
                    "DELETE FROM rust_resolution_unit_summary_versions;
             DELETE FROM resolution_unit_summary_versions WHERE lang='rust';
             DELETE FROM resolution_unit_summaries WHERE lang='rust';",
                )
            })
            .unwrap();
        let legacy = store
            .reconcile_unit_summaries(
                &snapshot,
                PreviousCfgSummaryReads,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap();
        assert!(legacy.failed.is_empty() && legacy.derived > 0, "{legacy:?}");
        // A header above this high-water mark cannot be a preexisting cache
        // hit: publish_unit creates a new header only after derive succeeds.
        let previous_summary_id: i64 = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT max(summary_id) FROM resolution_unit_summaries WHERE lang='rust'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(warm);
        let open_before = before
            .iter()
            .filter(|row| row.2.is_none())
            .collect::<Vec<_>>();
        assert!(
            open_before.iter().any(|row| row.1 == revision)
                && open_before.iter().any(|row| row.1 < revision),
            "the rotation must end rows opened at revision {revision} and before it: {before:?}"
        );

        // The rotation, and the oracle derived under the same version.
        set_derivation_version(None);
        let rotated = build();
        let scratch = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        );
        set_derivation_version(None);
        let rotated = rotated.expect("a derivation-version rotation on a warm store rebuilds");
        let scratch = scratch.expect("a from-scratch build under the new version succeeds");
        assert_eq!(
            head(&rotated),
            revision,
            "the rotation changes no file, so it opens no revision"
        );

        let derived_summary_ids = |analyzer: &WorkspaceAnalyzer| -> Vec<i64> {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .prepare("SELECT summary_id FROM resolution_unit_summaries WHERE lang='rust' AND summary_id>?1 ORDER BY summary_id")
                .unwrap()
                .query_map([previous_summary_id], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let derived = derived_summary_ids(&rotated);
        let live: Vec<i64> = rotated.store().unwrap().read_conn().unwrap()
            .prepare("SELECT summary_id FROM resolution_unit_summary_versions WHERE lang='rust' AND valid_until IS NULL ORDER BY summary_id")
            .unwrap().query_map([], |row| row.get(0)).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert!(!live.is_empty(), "the warm upgrade selects Rust summaries");
        assert!(
            live.iter().all(|id| derived.contains(id)),
            "every live summary was derived after reopening the old read set: live={live:?}, derived={derived:?}"
        );
        let warm_again = build().expect("a second warm start succeeds");
        assert_eq!(
            derived_summary_ids(&warm_again),
            derived,
            "the unchanged second warm start derives no additional summaries"
        );
        drop(warm_again);

        // History: rows closed before stay as they were, a row opened before
        // this revision is closed at it, and a row this revision opened is
        // withdrawn rather than closed.
        let after = versions(&rotated);
        let mut closed = before
            .iter()
            .filter(|row| row.2.is_some())
            .cloned()
            .chain(
                open_before
                    .iter()
                    .filter(|row| row.1 < revision)
                    .map(|row| (row.0.clone(), row.1, Some(revision), row.3.clone())),
            )
            .collect::<Vec<_>>();
        closed.sort();
        assert_eq!(
            after
                .iter()
                .filter(|row| row.2.is_some())
                .cloned()
                .collect::<Vec<_>>(),
            closed,
            "the rotation closes only rows that opened before revision {revision}"
        );
        let open_after = after
            .iter()
            .filter(|row| row.2.is_none())
            .collect::<Vec<_>>();
        assert_eq!(
            open_after.iter().map(|row| &row.0).collect::<Vec<_>>(),
            open_before.iter().map(|row| &row.0).collect::<Vec<_>>(),
            "every crate is still published, once"
        );
        assert!(
            open_after
                .iter()
                .zip(&open_before)
                .all(|(after, before)| after.1 == revision && after.3 != before.3),
            "every crate is re-derived onto a new topology at revision {revision}: {after:?}"
        );

        let rotated_rows = live_crate_rows(&rotated.store().unwrap().read_conn().unwrap());
        let scratch_rows = live_crate_rows(&scratch.store().unwrap().read_conn().unwrap());
        assert_eq!(
            rotated_rows
                .iter()
                .map(|(table, _)| table)
                .collect::<Vec<_>>(),
            scratch_rows
                .iter()
                .map(|(table, _)| table)
                .collect::<Vec<_>>()
        );
        for ((table, rotated), (_, scratch)) in rotated_rows.iter().zip(&scratch_rows) {
            assert_eq!(
                rotated, scratch,
                "{table}: the rotated store must publish what a from-scratch build under the new version publishes"
            );
        }
        for derived in [
            "rust_crate_exports",
            "rust_crate_imports",
            "rust_crate_gaps",
        ] {
            assert!(
                rotated_rows
                    .iter()
                    .any(|(table, rows)| table == derived && !rows.is_empty()),
                "the comparison covers derived rows in {derived}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#9737: a manifest-only dependency rename left a stale manifest link in the crate row"
    )]
    fn warm_manifest_currency_upgrade_rederives_crates() {
        if run_derivation_version_child() {
            return;
        }
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        let project = fixture();
        let build = || {
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .unwrap()
        };
        let old = RUST_CRATE_DERIVATION_VERSION
            .strip_suffix("-11111-certified-absent-module-topology")
            .unwrap()
            .strip_suffix("-11060-unplaced-module-topology")
            .unwrap()
            .strip_suffix("-10987-scoped-symlink-omissions")
            .unwrap()
            .strip_suffix("-9737-crate-manifest-currency")
            .unwrap();
        set_derivation_version(Some(old));
        let first = build();
        let row = |a: &WorkspaceAnalyzer| -> (i64, i64, i64) {
            a.store()
                .unwrap()
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT v.valid_from, v.manifest_file_version_id, f.valid_until IS NULL
                 FROM rust_crate_versions v JOIN workspace_file_versions f
                 ON f.file_version_id=v.manifest_file_version_id
                 WHERE v.valid_until IS NULL AND f.rel_path='app/Cargo.toml' LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap()
        };
        let before = row(&first);
        drop(first);
        // This edit changes manifest identity while preserving crate topology.
        project.file("app/Cargo.toml").write("[package]\nname='app'\nversion='0.2.0'\nedition='2021'\n[dependencies]\ndep={path='../dep',features=['on']}\n[dev-dependencies]\nhelper={path='../helper'}\n").unwrap();
        let edited = build();
        let after = row(&edited);
        assert!(
            after.0 > before.0,
            "manifest edits open a new crate version"
        );
        assert_ne!(after.1, before.1);
        assert_eq!(after.2, 1);
        // Seed the old producer's persisted stale link, under its real epoch.
        edited.store().unwrap().conn.execute_fixture(move |conn| {
            conn.execute("UPDATE rust_crate_versions SET manifest_file_version_id=?1 WHERE manifest_file_version_id=?2 AND valid_until IS NULL", rusqlite::params![before.1, after.1]).map(|_| ())
        }).unwrap();
        assert_eq!(row(&edited).2, 0);
        drop(edited);
        set_derivation_version(None);
        let upgraded = build();
        assert_eq!(row(&upgraded).2, 1);
        let WorkspaceAnalyzer::Multi(multi) = &upgraded else {
            panic!("no analyzer")
        };
        let rust = multi
            .delegates()
            .get(&brokk_bifrost_core::analyzer::model::Language::Rust)
            .unwrap()
            .analyzer();
        let rust = (rust as &dyn std::any::Any)
            .downcast_ref::<brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer>()
            .unwrap();
        let file = project.file("app/src/lib.rs");
        let routes =
            brokk_bifrost_rust::graph_support::RustSource::file_routes(rust, &file, None).unwrap();
        assert_eq!(
            routes.has_available_declared_dependency(&file, "dep"),
            Some(true)
        );
    }

    #[test]
    fn crate_topology_digests_follow_the_derivation_version() {
        if run_derivation_version_child() {
            return;
        }
        let project = fixture();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let snapshot = {
            let conn = store.read_conn().unwrap();
            let row: (String, i64, i64) = conn
                .query_row(
                    "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(row.0),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    row.1,
                ),
                revision: row.2,
            }
        };
        let topologies = |store: &AnalyzerStore| -> i64 {
            store
                .read_conn()
                .unwrap()
                .query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        // Rebinding is what the reconcile does when it finds the digest it
        // computed already published. It used to clear the version rows first,
        // because a same-revision rebind could not close and reopen a row at
        // its own revision; that limitation was the defect, and
        // `warm_derivation_version_rotation_replaces_same_revision_versions`
        // is the test that holds it closed.
        let rebind = |store: &AnalyzerStore| {
            store.reconcile_rust_crates(&snapshot).unwrap();
        };

        let before = current_crate_digests(&store.read_conn().unwrap());
        let published = topologies(store);
        assert!(!before.is_empty() && published > 0);

        rebind(store);
        assert_eq!(
            (
                current_crate_digests(&store.read_conn().unwrap()),
                topologies(store)
            ),
            (before.clone(), published),
            "an unchanged derivation version reuses every published topology"
        );

        set_derivation_version(Some("crate-derivation-version-test"));
        rebind(store);
        set_derivation_version(None);

        let after = current_crate_digests(&store.read_conn().unwrap());
        assert_eq!(
            after.iter().map(|row| &row.0).collect::<Vec<_>>(),
            before.iter().map(|row| &row.0).collect::<Vec<_>>(),
            "the same crates are bound"
        );
        assert!(
            after
                .iter()
                .zip(&before)
                .all(|(after, before)| after.1 != before.1),
            "a second derivation version gives every crate a different topology digest"
        );
        assert_eq!(
            topologies(store),
            published * 2,
            "and the reconcile derived the replacements instead of reusing the published rows"
        );

        // The first reconcile derived rows under the new version; this second
        // reconcile must reuse those rows rather than derive them again.
        set_derivation_version(Some("crate-derivation-version-test"));
        rebind(store);
        set_derivation_version(None);
        assert_eq!(
            (
                current_crate_digests(&store.read_conn().unwrap()),
                topologies(store)
            ),
            (after, published * 2),
            "a second reconcile under the bumped version reuses what the first one published"
        );
    }

    /// A trait implementation is a tier-1 row per blob and a derived crate row
    /// per topology.
    ///
    /// The fixture separates the three declarations an impl joins: the type in
    /// one file, the trait in a second, the impl in a third, so every row here
    /// is a cross-blob answer no interior scan could give. It then covers each
    /// shape the header can take: a bare name reached through a `use`, a
    /// qualified path, a generic head, a cross-crate trait, a cross-crate
    /// subject, an inline module, and a trait that resolves nowhere.
    #[test]
    #[hardwon("abeb38d6a105: trait impl headers were not persisted for cross-blob lookup")]
    fn crate_trait_impl_rows_resolve_both_header_paths_through_module_routes() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "dep/src/lib.rs",
                "pub trait DepTrait { fn d(); } pub struct DepType;",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n",
            )
            .file("app/src/lib.rs", "pub mod ty; pub mod tr; pub mod im;")
            .file(
                "app/src/ty.rs",
                "pub struct Foo; pub struct Wrapper<T>(pub T); pub struct Local;",
            )
            .file(
                "app/src/tr.rs",
                "pub trait Trait { fn frobnicate(); } pub trait LocalTrait { fn l(); }",
            )
            .file(
                "app/src/im.rs",
                concat!(
                    "use crate::tr::Trait;\n",
                    "use crate::ty::Local;\n",
                    "impl Trait for crate::ty::Foo {}\n",
                    "impl crate::tr::Trait for crate::ty::Wrapper<u8> {}\n",
                    "impl Trait for &crate::ty::Foo {}\n",
                    "impl dep::DepTrait for Local {}\n",
                    "impl crate::tr::LocalTrait for dep::DepType {}\n",
                    "impl Absent for Local {}\n",
                    "pub mod deep { use crate::tr::Trait; impl Trait for crate::ty::Foo {} }\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let app: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // Both ends of a derived row are declarations, so the test names them the
        // way a reader does: through the export row that declares them. A row
        // that carried the (crate, module, name) triple its spelling resolved
        // through could not be compared this way, which is the point of the key.
        let declaration = |crate_name: &str, module: &str, name: &str| -> (i64, i64) {
            conn.query_row(
                "SELECT exports.declaration_blob_id, exports.declaration_site
                 FROM rust_crate_exports AS exports
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 WHERE topology.crate_name=?1 AND topology.target_kind='lib'
                   AND exports.module_path=?2 AND exports.namespace='type'
                   AND exports.name=?3 AND exports.origin='declaration'",
                params![crate_name, module, name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or_else(|error| {
                panic!("{crate_name} {module}::{name} has a declaration row: {error}")
            })
        };
        let rows = conn
            .prepare(
                "SELECT subject_declaration_blob_id, subject_declaration_site,
                        trait_declaration_blob_id, trait_declaration_site, impl_site
                 FROM rust_crate_trait_impls WHERE topology_id=?1 ORDER BY 1,2,3,4,5",
            )
            .unwrap()
            .query_map([app], |row| {
                Ok((
                    (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?),
                    (row.get::<_, i64>(2)?, row.get::<_, i64>(3)?),
                    row.get::<_, i64>(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let gaps = conn
            .prepare(
                "SELECT subject, json(detail) FROM rust_crate_gaps
                 WHERE topology_id=?1 AND gap_kind='unresolved_trait_impl' ORDER BY 1",
            )
            .unwrap()
            .query_map([app], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let foo = declaration("app", "crate::ty", "Foo");
        let wrapper = declaration("app", "crate::ty", "Wrapper");
        let local = declaration("app", "crate::ty", "Local");
        let implemented = declaration("app", "crate::tr", "Trait");
        let local_trait = declaration("app", "crate::tr", "LocalTrait");
        let dep_type = declaration("dep", "crate", "DepType");
        let dep_trait = declaration("dep", "crate", "DepTrait");
        let placed_declaration = |(blob_id, source_site): (i64, i64), rel_path: &str| {
            let oid: String = conn
                .query_row("SELECT blob_oid FROM blobs WHERE id=?1", [blob_id], |row| {
                    row.get(0)
                })
                .unwrap();
            let declaration_id: u32 = conn
                .query_row(
                    "SELECT declaration_id FROM source_native_declaration_bridges
                     WHERE blob_id=?1 AND source_site=?2",
                    params![blob_id, source_site],
                    |row| row.get(0),
                )
                .unwrap();
            (
                Oid::from_str(&oid).unwrap(),
                declaration_id,
                rel_path.to_owned(),
            )
        };
        let placed_trait = placed_declaration(implemented, "app/src/tr.rs");
        let placed_foo = placed_declaration(foo, "app/src/ty.rs");
        let expected_impl_rows = conn
            .prepare(
                "SELECT DISTINCT impl_keys.blob_oid, impls.impl_rel_path,
                        impls.impl_declaration_id, subject_keys.blob_oid,
                        subject.declaration_id, impls.subject_rel_path
                 FROM rust_crate_trait_impls AS impls
                 JOIN blobs AS impl_keys ON impl_keys.id=impls.impl_blob_id
                 LEFT JOIN source_native_declaration_bridges AS subject
                   ON subject.blob_id=impls.subject_declaration_blob_id
                  AND subject.source_site=impls.subject_declaration_site
                 LEFT JOIN blobs AS subject_keys ON subject_keys.id=subject.blob_id
                 WHERE impls.topology_id=?1
                   AND impls.trait_declaration_blob_id=?2
                   AND impls.trait_declaration_site=?3
                   AND impls.trait_rel_path=?4
                 ORDER BY 1, 2, 3, 4, 5, 6",
            )
            .unwrap()
            .query_map(
                params![app, implemented.0, implemented.1, "app/src/tr.rs"],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<u32>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let actual_impl_rows = store
            .rust_trait_impl_rows(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(placed_trait.0, "rust"),
                placed_trait.1,
                &placed_trait.2,
            )
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.impl_blob.to_string(),
                    row.impl_rel_path,
                    row.impl_declaration,
                    row.subject
                        .map(|(blob, declaration, path)| (blob.to_string(), declaration, path)),
                )
            })
            .collect::<Vec<_>>();
        let expected_impl_rows = expected_impl_rows
            .into_iter()
            .map(
                |(blob, path, declaration, subject_blob, subject_declaration, subject_path)| {
                    (
                        blob,
                        path,
                        declaration,
                        subject_blob
                            .zip(subject_declaration)
                            .map(|(blob, declaration)| (blob, declaration, subject_path)),
                    )
                },
            )
            .collect::<Vec<_>>();
        assert_eq!(
            actual_impl_rows, expected_impl_rows,
            "Rust summary endpoints preserve the legacy placed impl and subject rows"
        );
        let actual_trait_spellings = store
            .rust_trait_impl_spellings(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(placed_trait.0, "rust"),
                placed_trait.1,
                &placed_trait.2,
            )
            .unwrap();
        let expected_trait_spellings = conn
            .prepare(
                "SELECT DISTINCT spelled.terminal_spelling
                 FROM rust_crate_trait_impls AS impls
                 JOIN resolution_trait_implementations AS spelled
                   ON spelled.blob_id=impls.impl_blob_id
                  AND spelled.side='trait' AND spelled.impl_site=impls.impl_site
                 WHERE impls.topology_id=?1
                   AND impls.trait_declaration_blob_id=?2
                   AND impls.trait_declaration_site=?3
                   AND impls.trait_rel_path=?4
                   AND spelled.terminal_spelling IS NOT NULL
                 ORDER BY 1",
            )
            .unwrap()
            .query_map(
                params![app, implemented.0, implemented.1, "app/src/tr.rs"],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            actual_trait_spellings, expected_trait_spellings,
            "Rust summary endpoints preserve the resolved source spellings"
        );
        let actual_types = store
            .rust_types_implementing(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(placed_trait.0, "rust"),
                placed_trait.1,
                &placed_trait.2,
            )
            .unwrap()
            .into_iter()
            .map(|(blob, declaration, path)| (blob.to_string(), declaration, path))
            .collect::<Vec<_>>();
        let expected_types = conn
            .prepare(
                "SELECT DISTINCT keys.blob_oid, bridge.declaration_id, impls.subject_rel_path
                 FROM rust_crate_trait_impls AS impls
                 JOIN source_native_declaration_bridges AS bridge
                   ON bridge.blob_id=impls.subject_declaration_blob_id
                  AND bridge.source_site=impls.subject_declaration_site
                 JOIN blobs AS keys ON keys.id=bridge.blob_id
                 WHERE impls.topology_id=?1
                   AND impls.trait_declaration_blob_id=?2
                   AND impls.trait_declaration_site=?3
                   AND impls.trait_rel_path=?4
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map(
                params![app, implemented.0, implemented.1, "app/src/tr.rs"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, u32, String)>>>()
            .unwrap();
        assert_eq!(
            actual_types, expected_types,
            "Rust summary endpoints preserve the types implementing a placed trait"
        );
        let actual_traits = store
            .rust_traits_implemented_by(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(placed_foo.0, "rust"),
                placed_foo.1,
                &placed_foo.2,
            )
            .unwrap()
            .into_iter()
            .map(|(blob, declaration, path)| (blob.to_string(), declaration, path))
            .collect::<Vec<_>>();
        let expected_traits = conn
            .prepare(
                "SELECT DISTINCT keys.blob_oid, bridge.declaration_id, impls.trait_rel_path
                 FROM rust_crate_trait_impls AS impls
                 JOIN source_native_declaration_bridges AS bridge
                   ON bridge.blob_id=impls.trait_declaration_blob_id
                  AND bridge.source_site=impls.trait_declaration_site
                 JOIN blobs AS keys ON keys.id=bridge.blob_id
                 WHERE impls.topology_id=?1
                   AND impls.subject_declaration_blob_id=?2
                   AND impls.subject_declaration_site=?3
                   AND impls.subject_rel_path=?4
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map(params![app, foo.0, foo.1, "app/src/ty.rs"], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, u32, String)>>>()
            .unwrap();
        assert_eq!(
            actual_traits, expected_traits,
            "Rust summary endpoints preserve traits implemented by a placed type"
        );
        let (impl_blob_id, impl_declaration, impl_rel_path): (i64, u32, String) = conn
            .query_row(
                "SELECT impl_blob_id, impl_declaration_id, impl_rel_path
                 FROM rust_crate_trait_impls
                 WHERE topology_id=?1 AND subject_declaration_blob_id=?2
                   AND subject_declaration_site=?3 AND subject_rel_path=?4
                   AND trait_declaration_blob_id=?5 AND trait_declaration_site=?6
                   AND impl_declaration_id IS NOT NULL
                 ORDER BY impl_site LIMIT 1",
                params![
                    app,
                    foo.0,
                    foo.1,
                    "app/src/ty.rs",
                    implemented.0,
                    implemented.1
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let impl_oid: String = conn
            .query_row(
                "SELECT blob_oid FROM blobs WHERE id=?1",
                [impl_blob_id],
                |row| row.get(0),
            )
            .unwrap();
        let actual_impl_traits = store
            .rust_traits_of_impl(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    Oid::from_str(&impl_oid).unwrap(),
                    "rust",
                ),
                impl_declaration,
                &impl_rel_path,
            )
            .unwrap()
            .into_iter()
            .map(|(blob, declaration, path)| (blob.to_string(), declaration, path))
            .collect::<Vec<_>>();
        let expected_impl_traits = conn
            .prepare(
                "SELECT DISTINCT keys.blob_oid, bridge.declaration_id, impls.trait_rel_path
                 FROM rust_crate_trait_impls AS impls
                 JOIN source_native_declaration_bridges AS bridge
                   ON bridge.blob_id=impls.trait_declaration_blob_id
                  AND bridge.source_site=impls.trait_declaration_site
                 JOIN blobs AS keys ON keys.id=bridge.blob_id
                 WHERE impls.impl_blob_id=?1 AND impls.impl_declaration_id=?2
                   AND impls.impl_rel_path=?3
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map(
                params![impl_blob_id, impl_declaration, impl_rel_path],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, u32, String)>>>()
            .unwrap();
        assert_eq!(
            actual_impl_traits, expected_impl_traits,
            "Rust summary endpoints preserve the trait declared by one placed impl item"
        );
        let mut expected = [
            (foo, implemented),
            (foo, implemented),
            (wrapper, implemented),
            (local, dep_trait),
            (dep_type, local_trait),
        ];
        expected.sort_unstable();
        assert_eq!(
            rows.iter().map(|row| (row.0, row.1)).collect::<Vec<_>>(),
            expected,
            "each half resolves to the declaration it names, by the route a name in the \
             impl's module already takes: a qualified path through the module walk, a bare \
             name through the module's import binding, an extern head into the dependency's \
             published exports"
        );
        assert_eq!(
            rows.iter().map(|row| row.2).collect::<BTreeSet<_>>().len(),
            5,
            "the five implementations sit at five impl sites, the two \
             `impl Trait for crate::ty::Foo` among them, one of which is in the inline \
             module `deep`: {rows:?}"
        );
        assert_eq!(
            gaps,
            [(
                "crate::im::Absent".into(),
                // The current source-fact producer assigns site 36 to this
                // unresolved impl header in the fixture.
                "{\"evidence\":[{\"side\":\"trait\",\"spelling\":\"Absent\",\"impl_site\":36,\
                 \"reason\":\"unbound\",\"target_module_path\":\"crate::im\"}]}"
                    .replace(" ", "")
            )],
            "a half that reaches no declaration names the half, the spelling, why it \
             reached none and the container its route reached, and its impl contributes \
             no row"
        );
        let summary_id: i64 = conn
            .query_row(
                "SELECT rust_summary.summary_id
                 FROM rust_crate_versions AS versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN rust_resolution_unit_summary_versions AS rust_summary
                   ON rust_summary.workspace_id=versions.workspace_id
                  AND rust_summary.lang=versions.lang
                  AND rust_summary.generation=versions.generation
                  AND rust_summary.unit_key=versions.crate_key
                  AND rust_summary.valid_from=versions.valid_from
                 WHERE versions.topology_id=?1 AND versions.valid_until IS NULL",
                [app],
                |row| row.get(0),
            )
            .unwrap();
        let resolved_endpoint_count: usize = conn
            .query_row(
                "SELECT count(*) FROM rust_resolution_unit_summary_trait_endpoints
                 WHERE summary_id=?1 AND endpoint_state='resolved'",
                [summary_id],
                |row| row.get(0),
            )
            .unwrap();
        let expected_resolved_endpoint_count: usize = conn
            .query_row(
                "SELECT (SELECT count(*) * 2 FROM rust_crate_trait_impls WHERE topology_id=?1)
                      + (SELECT count(*) FROM rust_crate_unresolved_trait_impls
                         WHERE topology_id=?1 AND side='subject' AND reason='resolved')",
                [app],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            resolved_endpoint_count, expected_resolved_endpoint_count,
            "each resolved legacy half publishes its endpoint once, including inline modules"
        );
        let inline_endpoint_count: usize = conn
            .query_row(
                "SELECT count(*) FROM rust_resolution_unit_summary_trait_endpoints
                 WHERE summary_id=?1 AND endpoint_state='resolved'
                   AND owner_module_path='crate::im::deep'",
                [summary_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            inline_endpoint_count, 2,
            "the inline impl's subject and trait stay in its innermost module placement"
        );
        let unresolved_endpoint_count: usize = conn
            .query_row(
                "SELECT count(*) FROM rust_resolution_unit_summary_trait_endpoints
                 WHERE summary_id=?1 AND endpoint_state='unresolved'",
                [summary_id],
                |row| row.get(0),
            )
            .unwrap();
        let expected_unresolved_endpoint_count: usize = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_unresolved_trait_impls
                 WHERE topology_id=?1 AND (side='trait' OR reason!='resolved')",
                [app],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unresolved_endpoint_count, expected_unresolved_endpoint_count,
            "incomplete trait halves and subjects without declarations stay unresolved in their owning summary"
        );
        let expected_unresolved_files = conn
            .prepare(
                "SELECT DISTINCT blobs.blob_oid, unresolved.impl_rel_path,
                        unresolved.impl_declaration_id
                 FROM rust_crate_unresolved_trait_impls AS unresolved
                 JOIN blobs ON blobs.id=unresolved.impl_blob_id
                 WHERE unresolved.topology_id=?1 AND unresolved.side='trait'
                   AND unresolved.spelling='Absent'
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map([app], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let actual_unresolved_files = store
            .rust_unresolved_trait_impl_files("Absent")
            .unwrap()
            .into_iter()
            .map(|(blob, path, declaration)| (blob.to_string(), path, declaration))
            .collect::<Vec<_>>();
        assert_eq!(
            actual_unresolved_files, expected_unresolved_files,
            "the live-summary spelling seek preserves the legacy unresolved trait candidates"
        );
    }

    /// Every Rust unit-summary reader observes the summary the writer just
    /// published.
    ///
    /// A derivation-version bump is what broke this: PR #5242 raised
    /// `RUST_UNIT_SUMMARY_DERIVATION_VERSION` to 8 and left five reader
    /// predicates at 7, so every freshly derived Rust crate summary became
    /// invisible to them and summary-backed lookups came back empty (#5249).
    /// Each reader now binds the writer's constant, and this test reads one
    /// derived workspace through every reader family that carries the
    /// predicate, so a reader that stops agreeing with the writer about which
    /// summaries exist fails here instead of silently returning nothing.
    #[test]
    #[hardwon("#5249: five readers kept derivation_version=7 after the writer moved to 8")]
    fn every_rust_unit_summary_reader_observes_a_freshly_published_summary() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "dep/src/lib.rs",
                "pub trait DepTrait { fn d(); } pub struct DepType;",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n\
                 [dependencies]\ndep={path=\"../dep\"}\n",
            )
            .file("app/src/lib.rs", "pub mod ty; pub mod tr; pub mod im;")
            .file("app/src/ty.rs", "pub struct Foo; pub struct Local;")
            .file("app/src/tr.rs", "pub trait Trait { fn frobnicate(); }")
            .file(
                "app/src/im.rs",
                concat!(
                    "use crate::tr::Trait;\n",
                    "use crate::ty::Local;\n",
                    "impl Trait for crate::ty::Foo {}\n",
                    "impl dep::DepTrait for Local {}\n",
                    "impl Absent for Local {}\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = conn
            .query_row(
                "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let snapshots: WorkspaceSnapshots = WorkspaceSnapshots::from_iter([(
            "rust".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace_id),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    generation,
                ),
                revision,
            },
        )]);

        // Anchor the reader side: the writer published both crates at the
        // readers' constant, so an empty answer below is a stale reader.
        let published: i64 = conn
            .query_row(
                "SELECT count(*) FROM resolution_unit_summaries
                 WHERE lang='rust' AND unit_kind='rust_crate'
                   AND publication_state='complete' AND derivation_version=?1",
                [brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            published, 2,
            "both workspace crates were derived and published"
        );

        let package_rows = store.rust_summary_package_rows(&snapshots).unwrap();
        let mut package_crates = package_rows
            .iter()
            .map(|row| row.crate_name.clone())
            .collect::<Vec<_>>();
        package_crates.sort_unstable();
        package_crates.dedup();
        assert_eq!(
            package_crates,
            ["app", "dep"],
            "the package reader observes every published summary: {package_rows:?}"
        );

        let route_rows = store.rust_summary_cargo_route_rows(&snapshots).unwrap();
        assert!(
            route_rows.iter().any(|row| {
                row.dependency_extern_name.as_deref() == Some("dep")
                    && row.dependency_boundary.as_deref() == Some("workspace")
            }),
            "the Cargo-route reader observes the workspace dependency edge: {route_rows:?}"
        );

        // Connection-scoped reads partition the same selected workspace.
        let selected_conn = store.read_conn_for_workspace(&snapshots).unwrap();
        let snapshot = &snapshots["rust"];
        let mut unit_keys = route_rows
            .iter()
            .map(|row| row.unit_key)
            .collect::<Vec<_>>();
        unit_keys.sort_unstable();
        unit_keys.dedup();
        assert_eq!(unit_keys.len(), 2);
        let mut all_packages = Vec::new();
        let mut all_routes = Vec::new();
        for unit_key in &unit_keys {
            let routes = AnalyzerStore::rust_summary_cargo_route_rows_for_unit(
                &selected_conn,
                snapshot,
                unit_key,
            )
            .unwrap();
            assert!(routes.iter().all(|row| &row.unit_key == unit_key));
            let crate_name = routes[0].crate_name.as_str();
            let packages = AnalyzerStore::rust_summary_package_rows_for_unit(
                &selected_conn,
                snapshot,
                unit_key,
            )
            .unwrap();
            assert!(packages.iter().all(|row| row.crate_name == crate_name));
            let mut expected = package_rows
                .iter()
                .filter(|row| row.crate_name == crate_name)
                .map(|row| format!("{row:?}"))
                .collect::<Vec<_>>();
            let mut actual = packages
                .iter()
                .map(|row| format!("{row:?}"))
                .collect::<Vec<_>>();
            expected.sort_unstable();
            actual.sort_unstable();
            assert_eq!(actual, expected);
            all_packages.extend(packages.into_iter().map(|row| format!("{row:?}")));
            all_routes.extend(routes.into_iter().map(|row| format!("{row:?}")));
        }
        let mut expected_packages = package_rows
            .iter()
            .map(|row| format!("{row:?}"))
            .collect::<Vec<_>>();
        let mut expected_routes = route_rows
            .iter()
            .map(|row| format!("{row:?}"))
            .collect::<Vec<_>>();
        all_packages.sort_unstable();
        all_routes.sort_unstable();
        expected_packages.sort_unstable();
        expected_routes.sort_unstable();
        assert_eq!(all_packages, expected_packages);
        assert_eq!(all_routes, expected_routes);

        let oids = package_rows
            .iter()
            .map(|row| Oid::from_str(&row.blob_oid).unwrap())
            .collect::<Vec<_>>();
        let key = brokk_bifrost_core::gitblob::BlobKey::unvaried(oids[0], "rust");
        let whole = store
            .rust_module_route_facts_while(&key, snapshot.generation, &oids, &|| true)
            .unwrap()
            .unwrap();
        let subset = &oids[..1];
        let scoped = AnalyzerStore::rust_module_route_facts_on_connection(
            &selected_conn,
            &key,
            snapshot.generation,
            subset,
            &|| true,
        )
        .unwrap()
        .unwrap();
        let restricted = whole
            .into_iter()
            .filter(|(oid, _)| subset.contains(oid))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(format!("{scoped:?}"), format!("{restricted:?}"));

        // The selected-unit fill is what every reader above joins, so a stale
        // predicate in it empties all of them.
        let selected: i64 = store
            .read_conn_for_workspace(&snapshots)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM temp.selected_rust_unit_summaries",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            selected >= 2,
            "the fill selected both published crates, got {selected}"
        );

        // The live-summary joins, asked through a placed trait declaration.
        let (trait_blob, trait_site): (i64, i64) = conn
            .query_row(
                "SELECT exports.declaration_blob_id, exports.declaration_site
                 FROM rust_crate_exports AS exports
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 WHERE topology.crate_name='app' AND topology.target_kind='lib'
                   AND exports.module_path='crate::tr' AND exports.namespace='type'
                   AND exports.name='Trait' AND exports.origin='declaration'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let trait_oid: String = conn
            .query_row(
                "SELECT blob_oid FROM blobs WHERE id=?1",
                [trait_blob],
                |row| row.get(0),
            )
            .unwrap();
        let trait_declaration: u32 = conn
            .query_row(
                "SELECT declaration_id FROM source_native_declaration_bridges
                 WHERE blob_id=?1 AND source_site=?2",
                params![trait_blob, trait_site],
                |row| row.get(0),
            )
            .unwrap();
        let trait_oid = Oid::from_str(&trait_oid).unwrap();
        let impl_rows = store
            .rust_trait_impl_rows(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(trait_oid, "rust"),
                trait_declaration,
                "app/src/tr.rs",
            )
            .unwrap();
        assert!(
            impl_rows
                .iter()
                .any(|row| row.impl_rel_path == "app/src/im.rs"),
            "the live-summary reader observes the derived impl row: {impl_rows:?}"
        );
        let spellings = store
            .rust_trait_impl_spellings(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(trait_oid, "rust"),
                trait_declaration,
                "app/src/tr.rs",
            )
            .unwrap();
        assert!(
            spellings.iter().any(|spelling| spelling == "Trait"),
            "the live-summary reader observes the trait spelling: {spellings:?}"
        );

        let unresolved = store.rust_unresolved_trait_impl_files("Absent").unwrap();
        assert!(
            unresolved
                .iter()
                .any(|(_, rel_path, _)| rel_path == "app/src/im.rs"),
            "the unresolved-trait reader observes the impl whose trait never bound: {unresolved:?}"
        );
    }

    /// `use super::*;` brings in what the parent module can name, and that
    /// includes the parent's own private `use` imports, named or glob: a
    /// private binding is in scope in the module that writes it and in every
    /// module below it. This is how a `#[cfg(test)] mod tests` names the trait
    /// its fixture implements, so an impl header written there resolves
    /// through the parent's imports, not only through the parent's own items.
    #[test]
    #[hardwon("141eef535530: use super glob missed parent private imports during impl binding")]
    fn crate_trait_impl_rows_bind_parent_private_imports_through_use_super_glob() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod tr; pub mod ty; mod named; mod globbed;",
            )
            .file("src/tr.rs", "pub trait Trait { fn f(); }")
            .file("src/ty.rs", "pub struct Foo;")
            .file(
                "src/named.rs",
                concat!(
                    "use crate::tr::Trait;\n",
                    "use crate::ty::Foo;\n",
                    "#[cfg(test)]\n",
                    "mod tests {\n",
                    "    use super::*;\n",
                    "    struct Fake;\n",
                    "    impl Trait for Fake { fn f() {} }\n",
                    "    impl Trait for Foo { fn f() {} }\n",
                    "    mod deeper { use super::*; impl Trait for Fake { fn f() {} } }\n",
                    "}\n",
                ),
            )
            .file(
                "src/globbed.rs",
                concat!(
                    "use crate::tr::*;\n",
                    "mod tests {\n",
                    "    use super::*;\n",
                    "    struct Fake;\n",
                    "    impl Trait for Fake { fn f() {} }\n",
                    "}\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT subject.module_path || '::' || subject.name,
                        implemented.module_path || '::' || implemented.name
                 FROM rust_crate_trait_impls AS impls
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN rust_crate_exports AS subject
                   ON subject.topology_id=impls.topology_id
                  AND subject.declaration_blob_id=impls.subject_declaration_blob_id
                  AND subject.declaration_site=impls.subject_declaration_site
                  AND subject.origin='declaration' AND subject.namespace='type'
                 JOIN rust_crate_exports AS implemented
                   ON implemented.topology_id=impls.topology_id
                  AND implemented.declaration_blob_id=impls.trait_declaration_blob_id
                  AND implemented.declaration_site=impls.trait_declaration_site
                  AND implemented.origin='declaration' AND implemented.namespace='type'
                 WHERE topology.crate_name='app' AND topology.target_kind='lib'
                 ORDER BY 1, 2",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let gaps = conn
            .prepare(
                "SELECT subject FROM rust_crate_gaps
                 WHERE gap_kind='unresolved_trait_impl' ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                (
                    "crate::globbed::tests::Fake".into(),
                    "crate::tr::Trait".into()
                ),
                (
                    "crate::named::tests::Fake".into(),
                    "crate::tr::Trait".into()
                ),
                (
                    "crate::named::tests::Fake".into(),
                    "crate::tr::Trait".into()
                ),
                ("crate::ty::Foo".into(), "crate::tr::Trait".into()),
            ],
            "each impl binds both halves through the parent's private imports: a named \
             `use` one glob away, the same `use` two globs away in a nested module, and a \
             private glob one glob away; unresolved: {gaps:?}"
        );
        assert!(gaps.is_empty(), "no half is left unbound: {gaps:?}");
    }
    /// Two byte-identical files declare one `(blob, site)`, so the relation
    /// keys each end by the file that declares it. When the impl names its
    /// trait through a re-export, the file is found by following the
    /// re-export to the declaring module, in this crate and across a crate
    /// boundary, not by picking among every file that declares those bytes.
    #[test]
    #[hardwon("fbca556b2ffc: byte-identical declarations at distinct placements were conflated")]
    fn crate_trait_impl_rows_place_each_end_in_its_declaring_file() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"dep\"]\nresolver=\"2\"\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "dep/src/lib.rs",
                "pub mod a; pub mod b; pub mod prelude { pub use crate::b::Shared; }",
            )
            .file("dep/src/a.rs", "pub trait Shared {}")
            .file("dep/src/b.rs", "pub trait Shared {}")
            .file(
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n",
            )
            .file(
                "app/src/lib.rs",
                "pub mod one; pub mod two; pub mod facade; pub mod worker;",
            )
            .file("app/src/one.rs", "pub trait Runnable {}")
            .file("app/src/two.rs", "pub trait Runnable {}")
            .file("app/src/facade.rs", "pub use crate::two::Runnable;")
            .file(
                "app/src/worker.rs",
                concat!(
                    "pub struct Worker;\n",
                    "impl crate::one::Runnable for Worker {}\n",
                    "impl crate::facade::Runnable for Worker {}\n",
                    "impl dep::prelude::Shared for Worker {}\n",
                ),
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT impls.subject_rel_path, impls.trait_rel_path, impls.impl_rel_path
                 FROM rust_crate_trait_impls AS impls
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 WHERE topology.crate_name='app' AND topology.target_kind='lib'
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let worker = || "app/src/worker.rs".to_string();
        assert_eq!(
            rows,
            [
                (worker(), "app/src/one.rs".to_string(), worker()),
                (worker(), "app/src/two.rs".to_string(), worker()),
                (worker(), "dep/src/b.rs".to_string(), worker()),
            ],
            "a direct path places the trait in its own file, a re-export in this crate \
             places it in the file the re-export names, and a re-export in a dependency \
             places it in that dependency's declaring file"
        );
        let unbridged: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_trait_impls WHERE impl_declaration_id IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let impl_items: Vec<i64> = conn
            .prepare(
                "SELECT DISTINCT impls.impl_declaration_id
                 FROM rust_crate_trait_impls AS impls
                 JOIN source_rust_impl_items AS item
                   ON item.blob_id=impls.impl_blob_id
                  AND item.declaration_id=impls.impl_declaration_id
                 ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            (unbridged, impl_items.len()),
            (0, 3),
            "every row names its impl item's source declaration, and the three impls \
             in worker.rs are three items: {impl_items:?}"
        );
    }

    #[test]
    fn crate_cross_crate_reexport_routes_become_exports_and_bindings() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"relay\",\"umbrella\",\"dep\"]\nresolver=\"2\"\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("dep/src/lib.rs", "pub mod inner { pub struct Name; }")
            .file(
                "umbrella/Cargo.toml",
                "[package]\nname=\"umbrella\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\n",
            )
            .file("umbrella/src/lib.rs", "pub use dep::inner;")
            .file(
                "relay/Cargo.toml",
                "[package]\nname=\"relay\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\numbrella={path=\"../umbrella\"}\n",
            )
            .file("relay/src/lib.rs", "pub use umbrella::inner;")
            .file(
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"../dep\"}\numbrella={path=\"../umbrella\"}\nrelay={path=\"../relay\"}\n",
            )
            .file(
                "app/src/lib.rs",
                "pub use dep::inner; pub mod facade; pub mod sub;",
            )
            .file(
                "app/src/facade.rs",
                "pub use dep::inner::Name; pub use dep::inner::Absent;",
            )
            .file(
                "app/src/sub.rs",
                "use crate::inner::Name; use crate::facade::Name as Viaf; use umbrella::inner::Name as Viau; use relay::inner::Name as Viar; pub fn make(_: Name, _: Viaf, _: Viau, _: Viar) {}",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let key = |name: &str| -> String {
            conn.query_row(
                "SELECT hex(crate_key) FROM rust_crate_topologies WHERE crate_name=?1 AND target_kind='lib'",
                [name],
                |row| row.get(0),
            )
            .unwrap()
        };
        let app: i64 = conn
            .query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let exports = conn.prepare("SELECT module_path, namespace, name, origin FROM rust_crate_exports WHERE topology_id=?1 AND name IN ('inner','Name','Absent') ORDER BY 1,2,3").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            exports,
            [
                (
                    "crate".into(),
                    "type".into(),
                    "inner".into(),
                    "reexport".into()
                ),
                (
                    "crate::facade".into(),
                    "type".into(),
                    "Name".into(),
                    "reexport".into()
                ),
                (
                    "crate::facade".into(),
                    "value".into(),
                    "Name".into(),
                    "reexport".into()
                ),
            ],
            "a re-export of a dependency name is an export row of the re-exporting module"
        );
        let bindings = conn.prepare("SELECT bound_name, namespace, hex(target_crate_key), target_module_path, target_name FROM rust_crate_imports WHERE topology_id=?1 AND module_path='crate::sub' ORDER BY 1,2").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let dep = key("dep");
        assert_eq!(
            bindings,
            [
                (
                    "Name".into(),
                    "type".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Name".into(),
                    "value".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viaf".into(),
                    "type".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viaf".into(),
                    "value".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viar".into(),
                    "type".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viar".into(),
                    "value".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viau".into(),
                    "type".into(),
                    dep.clone(),
                    "crate::inner".into(),
                    "Name".into()
                ),
                (
                    "Viau".into(),
                    "value".into(),
                    dep,
                    "crate::inner".into(),
                    "Name".into()
                ),
            ],
            "a path through a re-exported dependency module binds the dependency's export, \
             however many crates re-exported it on the way"
        );
        let gaps = conn.prepare("SELECT gap_kind, subject, json(detail) FROM rust_crate_gaps WHERE topology_id=?1 ORDER BY 1,2").unwrap().query_map([app], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            gaps,
            [(
                "unresolved_reexport".into(),
                "crate::facade::Absent".into(),
                "{\"evidence\":[{\"import_ordinal\":1,\"imported_name\":\"Absent\",\"target_crate\":\"dep\",\"target_module_path\":\"crate::inner\"}]}".into()
            )],
            "a name the dependency does not export stays a gap that names the dependency"
        );
    }

    #[test]
    fn crate_textual_macro_shadowing_requires_source_visibility_rows() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"textual\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file(
                "src/lib.rs",
                r#"
macro_rules! choose { () => { 1u8 }; }
pub mod first;
macro_rules! choose { () => { 2u8 }; }
pub mod second;
"#,
            )
            .file("src/first.rs", "pub fn value() -> u8 { choose!() }")
            .file("src/second.rs", "pub fn value() -> u8 { choose!() }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let definitions = conn
            .prepare(
                "SELECT definitions.blob_id, bridges.source_site
                 FROM source_rust_macro_definitions AS definitions
                 JOIN source_native_declaration_bridges AS bridges
                   USING(blob_id, declaration_id)
                 ORDER BY definitions.ordinal",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            definitions.len(),
            2,
            "source macro definitions: {definitions:?}"
        );
        let exports = conn
            .prepare(
                "SELECT declaration_blob_id, declaration_site
                 FROM rust_crate_exports
                 WHERE module_path='crate' AND namespace='macro' AND name='choose'
                 ORDER BY declaration_site",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(exports.len(), 1, "namespace exports: {exports:?}");
        // File-backed children inherit the textual environment at their mod
        // declaration, not the final namespace export of the parent module.
        let selected = conn
            .prepare(
                "SELECT modules.module_name, modules.blob_id,
                   (SELECT bridges.source_site FROM rust_item_macros AS macros
                    JOIN source_native_declaration_bridges AS bridges
                      ON bridges.blob_id=macros.blob_id
                     AND bridges.declaration_id=macros.declaration_id
                    WHERE macros.blob_id=modules.blob_id
                      AND macros.macro_name='choose'
                      AND macros.visible_after <= occurrence.start_byte
                      AND macros.scope_start <= occurrence.start_byte
                      AND occurrence.start_byte < macros.scope_end
                    ORDER BY macros.scope_end-macros.scope_start,
                             macros.visible_after DESC LIMIT 1)
                 FROM source_rust_module_declarations AS modules
                 JOIN source_declarations AS declarations USING(blob_id, declaration_id)
                 JOIN source_occurrences AS occurrence
                   ON occurrence.blob_id=declarations.blob_id
                  AND occurrence.occurrence_id=declarations.occurrence_id
                 ORDER BY modules.module_name",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i64>(1)?, row.get::<_, i64>(2)?),
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        eprintln!(
            "textual macro definitions={definitions:?}; namespace exports={exports:?}; inherited={selected:?}"
        );
        assert_eq!(
            selected,
            [
                ("first".to_owned(), definitions[0]),
                ("second".to_owned(), definitions[1])
            ]
        );
    }

    #[test]
    fn crate_include_splice_requires_multiple_blobs_at_one_module_path() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"splice\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", "include!(\"fragment.rs\");")
            .file("src/fragment.rs", "pub fn included() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_gaps WHERE gap_kind='unplaced_module'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let rows: i64 = conn.query_row("SELECT count(*) FROM rust_crate_container_sources s JOIN rust_crate_topologies t USING(topology_id) WHERE t.crate_name='splice' AND s.rel_path='src/fragment.rs' AND s.source_kind='include'", [], |row| row.get(0)).unwrap();
        assert_eq!(
            rows, 1,
            "the include splice must retain its own blob in the host namespace"
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_containers", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_container_sources",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(conn.query_row("SELECT count(*) FROM rust_crate_exports WHERE module_path='crate' AND name='included'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    }

    #[test]
    fn rust_crate_include_reached_from_cfg_exclusive_files_is_one_member() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"shared_include\"\nversion=\"0.1.0\"\nedition=\"2021\"\n\n[features]\ndefault=[\"std\"]\nstd=[]\n",
            )
            .file(
                "src/lib.rs",
                "#[cfg(feature = \"std\")]\ninclude!(\"std.rs\");\n#[cfg(not(feature = \"std\"))]\ninclude!(\"no_std.rs\");\n",
            )
            .file(
                "src/std.rs",
                "const STD_BRANCH: bool = true;\ninclude!(\"shared.rs\");\n",
            )
            .file(
                "src/no_std.rs",
                "const NO_STD_BRANCH: bool = true;\ninclude!(\"shared.rs\");\n",
            )
            .file("src/shared.rs", "pub fn shared() {}\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();

        let shared_sources = conn
            .prepare(
                "SELECT sources.rel_path, sources.source_kind
                 FROM rust_crate_container_sources AS sources
                 JOIN rust_crate_topologies AS topologies USING(topology_id)
                 WHERE topologies.crate_name='shared_include'
                   AND sources.rel_path='src/shared.rs'",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(shared_sources, [("src/shared.rs".into(), "include".into())]);
    }

    #[test]
    fn rust_crate_same_blob_included_at_two_paths_preserves_paths_once_per_export() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"same_content_include\"\nversion=\"0.1.0\"\nedition=\"2021\"\n\n[features]\ndefault=[\"mysql\",\"mariadb\"]\nmysql=[]\nmariadb=[]\n",
            )
            .file(
                "src/lib.rs",
                "#[cfg(feature = \"mysql\")]\ninclude!(\"mysql_schema.rs\");\n#[cfg(feature = \"mariadb\")]\ninclude!(\"mariadb_schema.rs\");\n",
            )
            .file("src/mysql_schema.rs", "pub fn shared() {}\n")
            .file("src/mariadb_schema.rs", "pub fn shared() {}\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        let shared_sources = conn
            .prepare(
                "SELECT sources.rel_path, sources.blob_id, sources.container_path
                 FROM rust_crate_container_sources AS sources
                 JOIN rust_crate_topologies AS topologies USING(topology_id)
                 WHERE topologies.crate_name='same_content_include'
                   AND sources.source_kind='include'
                 ORDER BY sources.rel_path",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(shared_sources.len(), 2, "both include paths must survive");
        assert_eq!(shared_sources[0].0, "src/mariadb_schema.rs");
        assert_eq!(shared_sources[1].0, "src/mysql_schema.rs");
        assert_eq!(shared_sources[0].1, shared_sources[1].1);
        assert_eq!(shared_sources[0].2, "crate");
        assert_eq!(shared_sources[1].2, "crate");
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_exports
                 WHERE module_path='crate' AND name='shared'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "identical member content contributes one semantic export",
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_container_members AS members
                 JOIN rust_crate_topologies AS topologies USING(topology_id)
                 WHERE topologies.crate_name='same_content_include'
                   AND members.container_path='crate'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2,
            "the shared-content member and lib root are distinct semantic members",
        );
    }

    #[test]
    fn crate_local_imports_require_binder_scope_in_the_natural_key() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname=\"binders\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
            .file("src/lib.rs", "pub mod a { pub struct X; } fn f() { use crate::a::X; } fn g() { use crate::a::X; }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_gaps WHERE gap_kind='unresolved_import'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_imports WHERE namespace='type' AND bound_name='X'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2, "both disjoint lexical binders must survive");
    }

    #[test]
    fn crate_module_walk_uses_revision_path_indexes_in_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id, lang, generation, revision FROM workspace_heads WHERE lang = 'rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("rust_crate_module_walk"));
            assert!(
                plan.iter().any(
                    |row| row.contains("idx_workspace_file_versions_snapshot_kind")
                        && row.contains("rel_path=?")
                ),
                "{state:?}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.contains("source_rust_module_routes_fk_scope_ordinal")),
                "{state:?}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.contains("source_rust_module_scopes_fk_parent_ordinal")),
                "{state:?}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|row| row.contains("SCAN files")
                    || row.contains("AUTOMATIC")
                    || row.contains("MATERIALIZE selected_workspace_file_versions")),
                "{state:?}: {plan:?}"
            );
        }
    }

    #[test]
    fn rust_unit_summary_reads_seek_in_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        let (workspace_id, generation, revision, epoch, unit_key, summary_id): (
            String,
            i64,
            i64,
            String,
            Vec<u8>,
            i64,
        ) = conn
            .query_row(
                "SELECT heads.workspace_id, heads.generation, heads.revision,
                        epochs.producer_epoch, topology.crate_key, summaries.summary_id
                 FROM workspace_heads AS heads
                 JOIN rust_crate_versions AS topology_versions
                   ON topology_versions.workspace_id = heads.workspace_id
                  AND topology_versions.lang = heads.lang
                  AND topology_versions.generation = heads.generation
                  AND topology_versions.valid_until IS NULL
                 JOIN rust_crate_topologies AS topology
                   ON topology.topology_id = topology_versions.topology_id
                 JOIN resolution_unit_summary_versions AS summary_versions
                   ON summary_versions.workspace_id = topology_versions.workspace_id
                  AND summary_versions.lang = topology_versions.lang
                  AND summary_versions.generation = topology_versions.generation
                  AND summary_versions.unit_key = topology_versions.crate_key
                  AND summary_versions.valid_until IS NULL
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id = summary_versions.summary_id
                 JOIN resolution_producer_epochs AS epochs ON epochs.lang = heads.lang
                 WHERE heads.lang = 'rust' AND topology.crate_name = 'app'
                   AND topology.target_kind = 'lib'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        let dependency_key: Vec<u8> = conn
            .query_row(
                "SELECT dependencies.dependency_crate_key
                 FROM rust_crate_versions AS versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN rust_crate_dependencies AS dependencies USING(topology_id)
                 JOIN rust_crate_topologies AS dependency
                   ON dependency.crate_key = dependencies.dependency_crate_key
                 WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
                   AND versions.generation = ?2 AND versions.valid_until IS NULL
                   AND topology.crate_name = 'app' AND dependency.crate_name = 'dep'",
                rusqlite::params![workspace_id, generation],
                |row| row.get(0),
            )
            .unwrap();
        let (namespace, identity_id): (String, i64) = conn
            .query_row(
                "SELECT namespace, identity_id FROM resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND visibility = 'exported' LIMIT 1",
                [summary_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let state_name = state.to_string();
            let mut live = pinned("rust_unit_summary_live_version");
            live.params = vec![
                Value::Text(workspace_id.clone()),
                Value::Text("rust".into()),
                Value::Integer(generation),
                Value::Blob(unit_key.clone()),
                Value::Integer(revision),
                Value::Text(epoch.clone()),
                Value::Integer(
                    brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
            ];
            let plan = explain_pin(&conn, &live);
            assert!(
                plan.iter()
                    .any(|row| row.starts_with("SEARCH versions USING PRIMARY KEY")),
                "live summary with {state_name}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.starts_with("SEARCH summaries USING INTEGER PRIMARY KEY")),
                "live summary with {state_name}: {plan:?}"
            );

            let mut export = pinned("rust_unit_summary_export_point");
            export.params = vec![
                Value::Integer(summary_id),
                Value::Text(namespace.clone()),
                Value::Integer(identity_id),
            ];
            let plan = explain_pin(&conn, &export);
            assert!(
                plan.iter().any(|row| row.starts_with("SEARCH")
                    && row.contains("resolution_unit_summary_exports USING PRIMARY KEY")),
                "export seek with {state_name}: {plan:?}"
            );

            let mut dependents = pinned("rust_unit_summary_dependents");
            dependents.params = vec![
                Value::Blob(dependency_key.clone()),
                Value::Text(workspace_id.clone()),
                Value::Text("rust".into()),
                Value::Integer(generation),
                Value::Blob(vec![0; 32]),
            ];
            let plan = explain_pin(&conn, &dependents);
            assert!(
                plan.first()
                    .is_some_and(|row| row.starts_with("SEARCH dependencies USING")
                        && row.contains("resolution_unit_summary_dependencies_unit")),
                "dependents with {state_name}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.starts_with("SEARCH versions USING")),
                "dependents version seek with {state_name}: {plan:?}"
            );
            assert!(
                plan.iter().all(|row| !row.contains("AUTOMATIC")
                    && !row.contains("TEMP B-TREE")
                    && !row.contains("CO-ROUTINE")),
                "unit summary seeks with {state_name}: {plan:?}"
            );
        }
    }
    #[test]
    #[hardwon("6d1790cd65dc: revisioned enum alternatives collided in crate exports")]
    fn crate_revisioned_enum_variant_alternatives_share_one_export_key() {
        let crate_name = "revisioned_enum_exports";
        derivation::begin_legacy_export_compare(crate_name);
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"revisioned_enum_exports\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                r#"
                    #[revisioned(revision = 2)]
                    #[derive(Clone, Copy)]
                    pub enum RecordType {
                        #[revision(end = 2, convert_fn = "upgrade_edge_v1", fields_name = "EdgeV1")]
                        Edge,
                        #[revision(start = 2)]
                        Edge { variant: u16 },
                    }
                "#,
            )
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let comparisons = derivation::take_legacy_export_compare_metrics(crate_name);
        assert_eq!(
            comparisons.len(),
            1,
            "legacy export comparison: {comparisons:?}"
        );
        let conn = analyzer.store().unwrap().read_conn().unwrap();

        let variants = conn
            .prepare(
                "SELECT namespace, name FROM rust_crate_exports
                 WHERE module_path='crate::RecordType' ORDER BY namespace, name",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            variants,
            vec![
                ("type".into(), "Edge".into()),
                ("value".into(), "Edge".into()),
            ]
        );

        let authored_bridges: i64 = conn
            .query_row(
                "SELECT count(DISTINCT bridge.declaration_id)
                 FROM rust_crate_container_sources AS owner
                 JOIN source_native_declaration_bridges AS bridge
                   ON bridge.blob_id=owner.blob_id
                 JOIN source_rust_declaration_properties AS property
                   ON property.blob_id=bridge.blob_id
                  AND property.declaration_id=bridge.declaration_id
                 JOIN source_declaration_units AS mapping
                   ON mapping.blob_id=bridge.blob_id
                  AND mapping.declaration_id=bridge.declaration_id
                 JOIN code_units AS unit
                   ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
                 WHERE owner.container_path='crate::RecordType'
                   AND property.declaration_kind=9 AND unit.identifier='Edge'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            authored_bridges, 2,
            "both authored revision alternatives retain bridges"
        );
    }

    #[test]
    #[hardwon("#4459: invalid enum and module collision aborted crate derivation")]
    fn crate_enum_variant_collision_keeps_first_declaration_export() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"enum_module_collision\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "enum Foo { X }\nmod Foo { pub static X: isize = 42; }\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();

        let rows = conn
            .prepare(
                "SELECT exports.origin, exports.declaration_site,
                        property.declaration_kind, unit.identifier
                 FROM rust_crate_exports AS exports
                 JOIN source_native_declaration_bridges AS bridge
                   ON bridge.blob_id=exports.declaration_blob_id
                  AND bridge.source_site=exports.declaration_site
                 JOIN source_rust_declaration_properties AS property
                   ON property.blob_id=bridge.blob_id
                  AND property.declaration_id=bridge.declaration_id
                 JOIN source_declaration_units AS mapping
                   ON mapping.blob_id=bridge.blob_id
                  AND mapping.declaration_id=bridge.declaration_id
                 JOIN code_units AS unit
                   ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
                 WHERE exports.module_path='crate::Foo'
                   AND exports.namespace='value' AND exports.name='X'",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(rows.len(), 1, "one crate export must win: {rows:?}");
        assert_eq!(rows[0].0, "declaration");
        assert_eq!(rows[0].2, 11, "the export site must be the static");
        assert_eq!(rows[0].3, "X");
        assert!(
            rows[0].1 > 0,
            "the static export must retain its source site"
        );
    }

    #[test]
    #[hardwon("0fbbe7878a33: crate enum named variant import has a persisted demand route")]
    fn crate_enum_named_variant_import_has_a_persisted_demand_route() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = \"enum_named\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("src/lib.rs", "pub enum Shape { Circle(u32), Square { side: u32 }, Empty } use Shape::Circle; pub fn select() -> Shape { Circle(1) }")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let variants = conn.prepare("SELECT namespace, name FROM rust_crate_exports WHERE module_path='crate::Shape' ORDER BY namespace, name")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            variants,
            vec![
                ("type".into(), "Circle".into()),
                ("type".into(), "Square".into()),
                ("value".into(), "Circle".into()),
                ("value".into(), "Empty".into()),
                ("value".into(), "Square".into()),
            ]
        );
        let imports = conn.prepare("SELECT namespace,target_module_path,target_name FROM rust_crate_imports WHERE bound_name='Circle' ORDER BY namespace")
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            imports,
            vec![
                ("type".into(), "crate::Shape".into(), "Circle".into()),
                ("value".into(), "crate::Shape".into(), "Circle".into())
            ]
        );
        let containers: i64 = conn.query_row("SELECT count(*) FROM rust_crate_containers container JOIN rust_crate_container_sources source USING(topology_id,container_path) JOIN resolution_member_scope_properties scope ON scope.blob_id=source.blob_id AND scope.scope_head_node_key=source.enum_scope_node_key WHERE container.kind='enum' AND container.container_path='crate::Shape' AND source.scope_ordinal IS NULL", [], |row| row.get(0)).unwrap();
        assert_eq!(containers, 1);
    }
    #[test]
    fn crate_rows_reconcile_cargo_modules_and_body_update() {
        let fixture = fixture();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let before = {
            let conn = store.read_conn().unwrap();
            let modules = conn.prepare("SELECT topologies.crate_name, topologies.target_kind, modules.container_path, sources.rel_path, modules.placement FROM rust_crate_topologies AS topologies JOIN rust_crate_containers AS modules USING(topology_id) JOIN rust_crate_container_sources AS sources USING(topology_id, container_path) ORDER BY 1, 2, 3")
                .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?))).unwrap().collect::<std::result::Result<Vec<_>, _>>().unwrap();
            assert!(
                modules.contains(&(
                    "dep".into(),
                    "lib".into(),
                    "crate::on".into(),
                    "dep/src/on.rs".into(),
                    "mod_declaration".into()
                )),
                "{modules:?}"
            );
            assert!(
                !modules
                    .iter()
                    .any(|row| row.0 == "dep" && row.2 == "crate::off"),
                "{modules:?}"
            );
            assert_eq!(
                modules
                    .iter()
                    .filter(|row| row.3 == "app/src/shared.rs")
                    .count(),
                2,
                "{modules:?}"
            );
            assert!(
                modules
                    .iter()
                    .any(|row| row.2 == "crate::m" && row.4 == "inline"),
                "{modules:?}"
            );
            assert!(
                modules
                    .iter()
                    .any(|row| row.2 == "crate::tests" && row.4 == "inline"),
                "{modules:?}"
            );
            assert!(
                modules
                    .iter()
                    .any(|row| row.3 == "detached.rs" && row.1 == "detached"),
                "{modules:?}"
            );
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        };
        let file = fixture.file("app/src/a.rs");
        file.write("use super::*; pub fn b() { let body = 2; } pub fn original() {}")
            .unwrap();
        let updated = analyzer.update(&BTreeSet::from([file]));
        let conn = updated.store().unwrap().read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM rust_crate_topologies", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            before + 1
        );
        let versions: (i64, i64, i64) = conn
            .query_row(
                "SELECT count(*), sum(valid_until IS NOT NULL),
                    sum(valid_until IS NULL AND valid_from =
                        (SELECT max(revision) FROM workspace_heads WHERE lang = 'rust'))
             FROM rust_crate_versions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            versions,
            (before + 1, 1, 1),
            "a body edit closes one version and opens exactly one replacement"
        );
    }

    #[test]
    #[hardwon("#5172: a warm version-8 summary omitted conditional import activation gaps")]
    fn cfg_if_warm_summary_rotation_preserves_unknown_imports() {
        use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RustUnitSummaries;

        use brokk_bifrost_analysis::analyzer::store::unit_summaries::ConsumedDependency;

        use brokk_bifrost_analysis::analyzer::store::unit_summaries::UnitInputs;

        use brokk_bifrost_analysis::analyzer::store::unit_summaries::UnitOutputs;

        use brokk_bifrost_analysis::analyzer::store::unit_summaries::UnitSummaryLanguage;

        // Reproduce the previous summary policy through the real producer.
        // Keep the source facts and inputs; version 8 omitted import gaps.
        struct PreviousCfgIfSummary;
        impl UnitSummaryLanguage for PreviousCfgIfSummary {
            fn lang(&self) -> &'static str {
                "rust"
            }
            fn unit_kind(&self) -> &'static str {
                "rust_crate"
            }
            fn derivation_version(&self) -> i64 {
                8
            }
            fn stage(&self, conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<()> {
                RustUnitSummaries.stage(conn, snapshot)
            }
            fn clear_stage(&self, conn: &Connection) -> Result<()> {
                RustUnitSummaries.clear_stage(conn)
            }
            fn inputs(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit_id: i64,
            ) -> Result<UnitInputs> {
                RustUnitSummaries.inputs(conn, snapshot, unit_id)
            }
            fn derive(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit: &UnitInputs,
                dependencies: &[ConsumedDependency],
                producer_epoch: &str,
            ) -> Result<UnitOutputs> {
                let mut outputs =
                    RustUnitSummaries.derive(conn, snapshot, unit, dependencies, producer_epoch)?;
                outputs.gaps.retain(|gap| {
                    gap.kind != "unknown_activation" || gap.subject != "crate::selected"
                });
                Ok(outputs)
            }
            fn write_language_rows(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit: &UnitInputs,
                dependencies: &[ConsumedDependency],
                summary_id: i64,
            ) -> Result<usize> {
                let written = RustUnitSummaries.write_language_rows(
                    conn,
                    snapshot,
                    unit,
                    dependencies,
                    summary_id,
                )?;
                let removed = conn.execute(
                    "DELETE FROM rust_resolution_unit_summary_gaps
                     WHERE summary_id=?1 AND gap_kind='unknown_activation'
                       AND subject='crate::selected'",
                    [summary_id],
                )?;
                Ok(written + removed)
            }
            fn write_language_version(
                &self,
                conn: &Connection,
                snapshot: &WorkspaceSnapshotId,
                unit: &UnitInputs,
                summary_id: i64,
            ) -> Result<usize> {
                RustUnitSummaries.write_language_version(conn, snapshot, unit, summary_id)
            }
        }

        let source = concat!(
            "pub mod helpers { pub fn first() {} pub fn second() {} }\n",
            "cfg_if::cfg_if! {\n",
            "    if #[cfg(unknown_build_flag)] {\n",
            "        pub fn only_first() {}\n",
            "        pub use crate::helpers::first as selected;\n",
            "    } else {\n",
            "        pub fn only_second() {}\n",
            "        pub use crate::helpers::second as selected;\n",
            "    }\n",
            "}\n",
            "pub fn caller() { selected(); }\n",
        );
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let snapshot = {
            let conn = store.read_conn().unwrap();
            conn.query_row(
                "SELECT workspace_id, generation, revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| {
                    Ok(WorkspaceSnapshotId {
                        workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(
                            row.get(0)?,
                        ),
                        lang: "rust".into(),
                        generation:
                            brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                                row.get(1)?,
                            ),
                        revision: row.get(2)?,
                    })
                },
            )
            .unwrap()
        };
        // Start the retained cache with an actual version-8 input digest and
        // normalized output, rather than editing a current digest's metadata.
        store
            .conn
            .execute_fixture(|conn| {
                conn.execute_batch(
                    "DELETE FROM rust_resolution_unit_summary_versions;
                     DELETE FROM resolution_unit_summary_versions WHERE lang='rust';
                     DELETE FROM resolution_unit_summaries WHERE lang='rust';",
                )
            })
            .unwrap();
        let legacy = store
            .reconcile_unit_summaries(
                &snapshot,
                PreviousCfgIfSummary,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap();
        assert_eq!(legacy.derived, 1, "{legacy:?}");
        assert!(legacy.failed.is_empty(), "{legacy:?}");
        let alias_gaps = || {
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM resolution_unit_summary_versions AS version
                     JOIN rust_resolution_unit_summary_gaps AS gap USING(summary_id)
                     WHERE version.valid_until IS NULL AND gap.gap_kind='unknown_activation'
                       AND gap.subject='crate::selected'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        };
        assert_eq!(alias_gaps(), 0, "the old summary omitted this import");
        store.reconcile_rust_unit_summaries(&snapshot).unwrap();
        assert_eq!(
            alias_gaps(),
            1,
            "the current producer must replace the old summary"
        );

        let lookup = |analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
            let params = serde_json::from_value(serde_json::json!({
                "references": [{
                    "path": "src/lib.rs",
                    "line": source.lines().count(),
                    "column": source.lines().last().unwrap().find("selected").unwrap() + 1
                }]
            }))
            .unwrap();
            serde_json::to_value(crate::searchtools::get_definitions_by_location(
                analyzer.analyzer(),
                params,
            ))
            .unwrap()
        };
        let warm = lookup(&analyzer);
        let fresh = lookup(&project.workspace_analyzer(AnalyzerConfig::default()));
        assert_eq!(warm["results"][0]["status"], "incomplete", "{warm:#}");
        assert_eq!(
            warm["results"][0]["status"], fresh["results"][0]["status"],
            "warm={warm:#}, fresh={fresh:#}"
        );
    }
    fn rust_listing_certificate(root: &std::path::Path) -> bool {
        use crate::analyzer::store::{RUST_SOURCE_LISTING_DERIVATION_VERSION, WorkspaceId};
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::FilesystemProject;
        use std::sync::Arc;

        let project = Arc::new(FilesystemProject::new(root).unwrap());
        let workspace =
            WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default()).unwrap();
        let store = workspace.store().unwrap();
        let workspace_id = WorkspaceId::for_root(root);
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace_id, &["rust".to_owned()])
            .unwrap();
        let snapshot = snapshots.get("rust").expect("published Rust revision");
        assert!(
            !store
                .rust_source_listing_complete(snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION + 1)
                .unwrap()
        );
        store
            .rust_source_listing_complete(snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
            .unwrap()
    }

    #[test]
    fn broad_complete_uses_target_and_listing_evidence() {
        for (name, manifest, source, expected) in [
            (
                "missing module",
                "[package]\nname = 'app'\nversion = '0.1.0'",
                "mod missing;\n",
                true,
            ),
            (
                "unknown target key",
                "[package]\nname = 'app'\nversion = '0.1.0'\n[lib]\nmystery = true",
                "pub fn app() {}\n",
                false,
            ),
            (
                "crate type",
                "[package]\nname = 'app'\nversion = '0.1.0'\n[lib]\ncrate-type = ['rlib']",
                "pub fn app() {}\n",
                true,
            ),
            (
                "external dependency",
                "[package]\nname = 'app'\nversion = '0.1.0'\n[dependencies]\nmissing = '1'",
                "pub fn app() {}\n",
                true,
            ),
        ] {
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", manifest)
                .file("src/lib.rs", source)
                .build();
            let analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            let conn = analyzer.store().unwrap().read_conn().unwrap();
            let (broad, inventory): (bool, bool) = conn
                .query_row(
                    "SELECT broad_complete, inventory_complete FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(broad, expected, "{name}");
            if name == "external dependency" {
                assert!(!inventory, "unretained dependency keeps inventory open");
            }
        }
    }

    #[test]
    #[hardwon(
        "#9737: active duplicate module files were dropped from the broad relation while broad_complete held"
    )]
    fn active_duplicate_module_files_remain_broad_candidates() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
            .file("src/lib.rs", "mod foo;\n")
            .file("src/foo.rs", "pub fn a() {}\n")
            .file("src/foo/mod.rs", "pub fn b() {}\n")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        let mut broad = conn
            .prepare("SELECT rel_path, activation FROM rust_crate_broad_placements WHERE module_path='crate::foo' ORDER BY rel_path")
            .unwrap();
        let rows = broad
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            [("src/foo.rs".into(), -1), ("src/foo/mod.rs".into(), -1)]
        );
        let gaps: i64 = conn
            .query_row("SELECT count(*) FROM rust_crate_gaps WHERE gap_kind='duplicate_placement' AND subject='crate::foo'", [], |row| row.get(0))
            .unwrap();
        assert!(gaps > 0, "selected duplicate gap remains");
    }

    #[test]
    fn uncertified_active_edit_stays_scoped_and_matches_fresh_rows() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\n[lib]\nmystery=true",
            )
            .file("src/lib.rs", "pub fn app() {}")
            .build();
        let mut analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace_id),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        assert!(matches!(
            store
                .rust_crate_reconcile_scope(&snapshot, snapshot.revision, &["src/lib.rs".into()])
                .unwrap(),
            CrateReconcileScope::Reached { .. }
        ));
        let file = fixture.file("src/lib.rs");
        file.write("pub fn app() { let x = 1; let _ = x; }")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([file]));
        let fresh = fixture.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            current_crate_digests(&analyzer.store().unwrap().read_conn().unwrap()),
            current_crate_digests(&fresh.store().unwrap().read_conn().unwrap())
        );
    }

    #[test]
    fn broad_complete_covers_manifest_and_source_boundaries() {
        for (name, root_manifest, app_manifest, extra_path, extra_source, expected) in [
            (
                "missing explicit bin",
                "",
                "[package]\nname='app'\nversion='0.1.0'\n[[bin]]\nname='missing'\npath='src/missing.rs'",
                "",
                "",
                false,
            ),
            (
                "malformed member",
                "[workspace]\nmembers=[42]",
                "[package]\nname='app'\nversion='0.1.0'",
                "",
                "",
                false,
            ),
            (
                "invalid member glob",
                "[workspace]\nmembers=['[bad']",
                "[package]\nname='app'\nversion='0.1.0'",
                "",
                "",
                false,
            ),
            (
                "harness false",
                "",
                "[package]\nname='app'\nversion='0.1.0'\n[lib]\nharness=false",
                "",
                "",
                true,
            ),
            (
                "edition 2015 unlisted bin",
                "",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2015'\n[[bin]]\nname='listed'\npath='src/main.rs'",
                "src/bin/x.rs",
                "fn main() {}",
                true,
            ),
            (
                "implicit path member",
                "[workspace]\nmembers=['app']",
                "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\nhelper={path='../helper'}",
                "helper/src/lib.rs",
                "pub fn helper() {}",
                true,
            ),
        ] {
            let mut project = InlineTestProject::new()
                .file("app/Cargo.toml", app_manifest)
                .file("app/src/lib.rs", "pub fn app() {}");
            if !root_manifest.is_empty() {
                project = project.file("Cargo.toml", root_manifest);
            }
            if !extra_path.is_empty() {
                project = project.file(extra_path, extra_source);
            }
            if name == "edition 2015 unlisted bin" {
                project = project.file("app/src/main.rs", "fn main() {}");
            }
            if name == "implicit path member" {
                project = project.file(
                    "helper/Cargo.toml",
                    "[package]\nname='helper'\nversion='0.1.0'",
                );
            }
            let fixture = project.build();
            let analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            let conn = analyzer.store().unwrap().read_conn().unwrap();
            let broad: bool = conn.query_row(
                "SELECT broad_complete FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                [], |row| row.get(0)).unwrap();
            assert_eq!(broad, expected, "{name}");
        }
    }

    #[test]
    #[hardwon(
        "#11111: certified absence accepted an escaping #[path] or include! whose candidates the workspace cannot represent"
    )]
    fn broad_complete_refuses_unrepresentable_module_paths() {
        for (name, lib, expected) in [
            (
                "certified absent module",
                "mod missing; pub fn app() {}",
                true,
            ),
            (
                "escaping path module",
                "#[path = \"../../outside.rs\"] mod outside; pub fn app() {}",
                false,
            ),
            (
                "escaping include",
                "include!(\"../../outside.rs\"); pub fn app() {}",
                false,
            ),
            (
                "child of escaping inline path",
                "#[path = \"../../outside\"] mod outside { mod inner; } pub fn app() {}",
                false,
            ),
            (
                "inactive escaping path module",
                "#[cfg(any())] #[path = \"../../outside.rs\"] mod outside; pub fn app() {}",
                true,
            ),
        ] {
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
                .file("src/lib.rs", lib)
                .build();
            let analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            let conn = analyzer.store().unwrap().read_conn().unwrap();
            let broad: bool = conn
                .query_row(
                    "SELECT broad_complete FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(broad, expected, "{name}");
        }
    }

    #[test]
    fn broad_complete_refuses_unpublished_rust_source() {
        for (name, bytes) in [
            ("refused", b"\0".to_vec()),
            ("oversized", vec![b' '; 1024 * 1024 + 1]),
        ] {
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
                .file("src/lib.rs", "pub fn app() {}")
                .build();
            std::fs::write(fixture.file("src/extra.rs").abs_path(), bytes).unwrap();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let broad: bool = analyzer.store().unwrap().read_conn().unwrap().query_row(
                "SELECT broad_complete FROM rust_crate_topologies WHERE crate_name='app' AND target_kind='lib'",
                [], |row| row.get(0)).unwrap();
            assert!(!broad, "{name}");
        }
    }

    /// Shaped like bat's tests/integration_tests.rs: about a thousand lines
    /// of ordinary Rust with short lines, more than 65,536 AST nodes (the old
    /// whole-tree cap), and one string line longer than the default line limit.
    /// Numeric tables supply the nodes, which keeps the analyzer build small.
    #[test]
    #[hardwon(
        "#10694: one long string line refused an ordinary Rust file and left the listing uncertified"
    )]
    fn a_long_string_line_keeps_an_ordinary_rust_file_and_its_listing() {
        let mut integration = String::new();
        let row = format!("        {}\n", "1, ".repeat(50));
        for index in 0..40 {
            integration.push_str(&format!(
                "#[test]\nfn case_{index}() {{\n    let values = [\n{}    ];\n    assert_eq!(values.len(), 1000);\n}}\n",
                row.repeat(20)
            ));
        }
        integration.push_str(&format!(
            "#[test]\nfn long_expected_output() {{\n    let expected = \"{}\";\n    assert!(!expected.is_empty());\n}}\n",
            "\\x1b[38;5;231mline\\x1b[0m\\n".repeat(700)
        ));
        let longest = integration.lines().map(str::len).max().unwrap();
        assert!(longest > 16_000, "{longest}");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&integration, None).unwrap();
        assert!(!tree.root_node().has_error());
        assert!(tree.root_node().descendant_count() > 65_536);
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'",
            )
            .file("src/lib.rs", "pub fn app() {}\n")
            .file("tests/integration_tests.rs", &integration)
            .build();
        let analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(rust_head_listing_certificate(&analyzer), (true, vec![]));
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        let incomplete: Vec<(String, String)> = conn
            .prepare(
                "SELECT t.crate_name, t.target_kind FROM rust_crate_versions v
                 JOIN rust_crate_topologies t USING(topology_id)
                 WHERE v.valid_until IS NULL AND NOT t.broad_complete",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(incomplete, Vec::<(String, String)>::new());
        let names: BTreeSet<String> = analyzer
            .analyzer()
            .declarations(&fixture.file("tests/integration_tests.rs"))
            .into_iter()
            .map(|unit| unit.short_name().to_owned())
            .collect();
        assert!(names.contains("case_39"), "{names:?}");
        assert!(names.contains("long_expected_output"), "{names:?}");
    }

    #[test]
    fn detached_topology_requires_complete_traversed_source() {
        let fixture = InlineTestProject::new()
            .file("orphan.rs", "mod child;\n")
            .file("child.rs", "pub fn child() {}\n")
            .build();
        let broad = || {
            let analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            analyzer.store().unwrap().read_conn().unwrap().query_row(
                "SELECT broad_complete FROM rust_crate_topologies WHERE target_kind='detached' AND crate_name='orphan.rs' ORDER BY topology_id DESC LIMIT 1",
                [], |row| row.get::<_, bool>(0),
            ).unwrap()
        };
        assert!(broad());
        std::fs::write(fixture.file("child.rs").abs_path(), b"\0").unwrap();
        assert!(!broad());
    }

    #[test]
    fn stale_listing_certificate_scopes_edits_and_module_creation() {
        use brokk_bifrost_analysis::analyzer::store::{
            GenerationId, RUST_SOURCE_LISTING_DERIVATION_VERSION, WorkspaceId,
        };
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
            .file("src/lib.rs", "pub fn app() {}")
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: WorkspaceId(workspace_id),
            lang: "rust".into(),
            generation: GenerationId::from_persisted(generation),
            revision,
        };
        overwrite_rust_listing_certificate(
            store,
            &snapshot,
            RUST_SOURCE_LISTING_DERIVATION_VERSION - 1,
            vec![],
        );
        store.reconcile_rust_crates(&snapshot).unwrap();
        assert!(matches!(
            store
                .rust_crate_reconcile_scope(&snapshot, revision, &["src/lib.rs".into()])
                .unwrap(),
            CrateReconcileScope::Reached { .. }
        ));
        assert!(matches!(
            store
                .rust_crate_reconcile_scope(&snapshot, revision, &["src/new.rs".into()])
                .unwrap(),
            CrateReconcileScope::Reached { .. }
        ));
        let broad: bool = store.read_conn().unwrap().query_row(
            "SELECT t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.crate_name='app' AND t.target_kind='lib'",
            [], |row| row.get(0)).unwrap();
        assert!(!broad);
    }

    #[test]
    fn absorbed_detached_helper_matches_fresh_rows() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
            .file("src/lib.rs", "mod new;")
            .file("src/new/helper.rs", "pub fn helper() {}")
            .build();
        let analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let file = fixture.file("src/new.rs");
        file.write("mod helper;").unwrap();
        let analyzer = analyzer.update(&BTreeSet::from([file]));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            live_crate_rows(&analyzer.store().unwrap().read_conn().unwrap()),
            live_crate_rows(&fresh.store().unwrap().read_conn().unwrap())
        );
    }

    #[test]
    fn removed_module_becomes_detached_matches_fresh_rows() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
            .file("src/lib.rs", "mod x;")
            .file("src/x.rs", "pub fn x() {}")
            .build();
        let analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let file = fixture.file("src/lib.rs");
        file.write("pub fn root() {}").unwrap();
        let analyzer = analyzer.update(&BTreeSet::from([file]));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            live_crate_rows(&analyzer.store().unwrap().read_conn().unwrap()),
            live_crate_rows(&fresh.store().unwrap().read_conn().unwrap())
        );
    }

    // Recorded probes scope path-set events, including cross-crate case matches.
    #[test]
    fn path_probe_creation_scope_matches_fresh_rows() {
        for (path, everything, reached) in
            [("app/src/new.rs", false, 2), ("app/tests/new.rs", true, 0)]
        {
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[workspace]\nmembers=['app','peer','other']")
                .file("app/Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
                .file("app/src/lib.rs", "mod new;")
                .file("peer/Cargo.toml", "[package]\nname='peer'\nversion='0.1.0'")
                .file(
                    "peer/src/lib.rs",
                    "#[path=\"../../app/src/New.rs\"] mod probe;",
                )
                .file(
                    "other/Cargo.toml",
                    "[package]\nname='other'\nversion='0.1.0'",
                )
                .file("other/src/lib.rs", "pub fn other() {}")
                .build();
            let mut analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let snapshot = store.read_conn().unwrap().query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'", [], |row| Ok(WorkspaceSnapshotId {
                    workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(row.get(0)?),
                    lang: "rust".into(), generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(row.get(1)?), revision: row.get(2)?,
                })).unwrap();
            match store
                .rust_crate_reconcile_scope(&snapshot, snapshot.revision, &[path.into()])
                .unwrap()
            {
                CrateReconcileScope::Everything => assert!(everything),
                CrateReconcileScope::Reached { crates, .. } => {
                    assert!(!everything);
                    assert_eq!(crates.len(), reached);
                }
            }
            let file = fixture.file(path);
            std::fs::create_dir_all(file.abs_path().parent().unwrap()).unwrap();
            file.write("pub fn new() {}").unwrap();
            analyzer = analyzer.update(&BTreeSet::from([file]));
            let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            assert_eq!(
                live_crate_rows(&analyzer.store().unwrap().read_conn().unwrap()),
                live_crate_rows(&fresh.store().unwrap().read_conn().unwrap()),
                "{path}"
            );
        }
    }

    #[test]
    #[hardwon("#10552: deleting a required target root left other crates broad-complete")]
    fn deleting_required_custom_root_matches_fresh_rows() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=['app','other']")
            .file(
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\n[lib]\npath='custom.rs'",
            )
            .file("app/custom.rs", "pub fn app() {}")
            .file(
                "other/Cargo.toml",
                "[package]\nname='other'\nversion='0.1.0'",
            )
            .file("other/src/lib.rs", "pub fn other() {}")
            .build();
        let mut analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let file = fixture.file("app/custom.rs");
        std::fs::remove_file(file.abs_path()).unwrap();
        analyzer = analyzer.update(&BTreeSet::from([file]));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            live_crate_rows(&analyzer.store().unwrap().read_conn().unwrap()),
            live_crate_rows(&fresh.store().unwrap().read_conn().unwrap())
        );
    }

    #[test]
    fn certified_inactive_edit_scopes_to_its_crate() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=['app','dep']")
            .file(
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\ndep={path='../dep'}",
            )
            .file("app/src/lib.rs", "pub fn app() {}")
            .file("dep/Cargo.toml", "[package]\nname='dep'\nversion='0.1.0'")
            .file(
                "dep/src/lib.rs",
                "#[cfg(feature='off')] mod off; pub fn dep() {}",
            )
            .file("dep/src/off.rs", "pub fn inactive() {}")
            .build();
        let mut analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace_id),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let scope = store
            .rust_crate_reconcile_scope(&snapshot, revision, &["dep/src/off.rs".into()])
            .unwrap();
        match scope {
            // The inactive file belongs to dep's broad walk and its own
            // detached topology; both must be reached, while app is carried.
            CrateReconcileScope::Reached { crates, .. } => assert_eq!(crates.len(), 2),
            CrateReconcileScope::Everything => {
                let rows: Vec<(String, bool)> = store.read_conn().unwrap().prepare("SELECT t.crate_name,t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL").unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?))).unwrap().map(|row| row.unwrap()).collect();
                panic!("certified inactive placement must scope: {rows:?}")
            }
        }
        let off = fixture.file("dep/src/off.rs");
        off.write("pub fn inactive() { let changed = 1; let _ = changed; }")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([off]));
        let warm = current_crate_digests(&analyzer.store().unwrap().read_conn().unwrap());
        let cold = fixture.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            warm,
            current_crate_digests(&cold.store().unwrap().read_conn().unwrap())
        );
    }

    #[test]
    fn rust_scoped_file_creation_deletion_and_rename_match_fresh_rows() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
            .file(
                "src/lib.rs",
                "mod missing; #[cfg(feature='off')] mod inactive; #[path=\"../outside.rs\"] mod outside; include!(\"../included.rs\");",
            )
            .file("src/inactive.rs", "pub fn inactive() {}")
            .file("outside.rs", "pub fn outside() {}")
            .file("included.rs", "pub fn included() {}")
            .build();
        let mut analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let mut check = |path: &str| {
            let file = fixture.file(path);
            analyzer = analyzer.update(&BTreeSet::from([file]));
            let fresh = fixture.workspace_analyzer(AnalyzerConfig::default());
            let warm_rows = live_crate_rows(&analyzer.store().unwrap().read_conn().unwrap());
            let fresh_rows = live_crate_rows(&fresh.store().unwrap().read_conn().unwrap());
            assert_eq!(warm_rows.len(), fresh_rows.len(), "{path}: crate count");
            for ((name, warm), (_, cold)) in warm_rows.iter().zip(&fresh_rows) {
                assert_eq!(warm, cold, "{path}: {name}");
            }
        };
        std::fs::write(
            fixture.file("src/missing.rs").abs_path(),
            "pub fn found() {}",
        )
        .unwrap();
        check("src/missing.rs");
        fixture
            .file("outside.rs")
            .write("pub fn outside() { let n = 1; let _ = n; }")
            .unwrap();
        check("outside.rs");
        fixture
            .file("included.rs")
            .write("pub fn included() { let n = 1; let _ = n; }")
            .unwrap();
        check("included.rs");
        std::fs::remove_file(fixture.file("src/inactive.rs").abs_path()).unwrap();
        check("src/inactive.rs");
        std::fs::rename(
            fixture.file("src/missing.rs").abs_path(),
            fixture.file("src/renamed.rs").abs_path(),
        )
        .unwrap();
        drop(check);
        analyzer = analyzer.update(&BTreeSet::from([
            fixture.file("src/missing.rs"),
            fixture.file("src/renamed.rs"),
        ]));
        let fresh = fixture.workspace_analyzer(AnalyzerConfig::default());
        let warm_rows = live_crate_rows(&analyzer.store().unwrap().read_conn().unwrap());
        let fresh_rows = live_crate_rows(&fresh.store().unwrap().read_conn().unwrap());
        for ((name, warm), (_, cold)) in warm_rows.iter().zip(&fresh_rows) {
            assert_eq!(warm, cold, "rename: {name}");
        }
    }

    // `#[path = "Real.rs"]` matches src/real.rs only by case, so the lib crate
    // is not broad-complete although no module places real.rs. Deleting real.rs
    // proves Real.rs absent: the scoped reconcile must reach the lib crate,
    // which has no placement row for the deleted path.
    #[test]
    fn deleting_a_file_a_candidate_matched_by_case_matches_fresh_rows() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
            .file("src/lib.rs", "#[path = \"Real.rs\"] mod x; pub fn app() {}")
            .file("src/real.rs", "pub fn real() {}")
            .build();
        let lib_broad_complete = |conn: &Connection| -> bool {
            conn.query_row(
                "SELECT t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.crate_name='app' AND t.target_kind='lib'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        let mut analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert!(!lib_broad_complete(
            &analyzer.store().unwrap().read_conn().unwrap()
        ));
        let real = fixture.file("src/real.rs");
        std::fs::remove_file(real.abs_path()).unwrap();
        analyzer = analyzer.update(&BTreeSet::from([real]));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let fresh = fresh.store().unwrap().read_conn().unwrap();
        assert!(
            lib_broad_complete(&fresh),
            "Real.rs is proven absent once real.rs is gone"
        );
        let warm = analyzer.store().unwrap().read_conn().unwrap();
        assert_eq!(live_crate_rows(&warm), live_crate_rows(&fresh));
        drop(warm);
        drop(fresh);
        let exact = fixture.file("src/Real.rs");
        exact.write("pub fn found() {}").unwrap();
        analyzer = analyzer.update(&BTreeSet::from([exact]));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let warm = analyzer.store().unwrap().read_conn().unwrap();
        let fresh = fresh.store().unwrap().read_conn().unwrap();
        assert!(
            lib_broad_complete(&warm),
            "an exactly placed module is complete"
        );
        assert_eq!(live_crate_rows(&warm), live_crate_rows(&fresh));
    }

    // A selected src/foo.RS is a Rust source, and `#[path = "Foo.rs"]` matches it
    // by case, so creating it must reach the crate the way a fresh build does.
    #[test]
    fn creating_an_upper_case_rs_file_a_candidate_matches_by_case_matches_fresh_rows() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='app'\nversion='0.1.0'")
            .file("src/lib.rs", "#[path = \"Foo.rs\"] mod x; pub fn app() {}")
            .build();
        let lib_broad_complete = |conn: &Connection| -> bool {
            conn.query_row(
                "SELECT t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.crate_name='app' AND t.target_kind='lib'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        let mut analyzer = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert!(lib_broad_complete(
            &analyzer.store().unwrap().read_conn().unwrap()
        ));
        let created = fixture.file("src/foo.RS");
        created.write("pub fn foo() {}").unwrap();
        analyzer = analyzer.update(&BTreeSet::from([created]));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let fresh = fresh.store().unwrap().read_conn().unwrap();
        assert!(
            !lib_broad_complete(&fresh),
            "Foo.rs is not proven absent next to foo.RS"
        );
        let warm = analyzer.store().unwrap().read_conn().unwrap();
        assert_eq!(live_crate_rows(&warm), live_crate_rows(&fresh));
        drop(warm);
        drop(fresh);
        let exact = fixture.file("src/Foo.rs");
        exact.write("pub fn found() {}").unwrap();
        analyzer = analyzer.update(&BTreeSet::from([exact]));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let warm = analyzer.store().unwrap().read_conn().unwrap();
        let fresh = fresh.store().unwrap().read_conn().unwrap();
        let exact_listed = fixture
            .certified_project_dyn()
            .authoritative_files()
            .unwrap()
            .iter()
            .any(|file| file.rel_path() == Path::new("src/Foo.rs"));
        assert_eq!(lib_broad_complete(&warm), exact_listed);
        assert_eq!(live_crate_rows(&warm), live_crate_rows(&fresh));
    }

    #[test]
    fn rust_listing_certificate_tracks_source_refusals_and_other_files() {
        for (name, extra, expected) in [
            ("clean", None, true),
            (
                "large-rust",
                Some(("large.rs", vec![b' '; 1024 * 1024 + 1])),
                false,
            ),
            (
                "large-text",
                Some(("large.txt", vec![b' '; 1024 * 1024 + 1])),
                true,
            ),
            ("refused-rust", Some(("refused.rs", b"\0".to_vec())), false),
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
            if let Some((path, bytes)) = extra {
                std::fs::write(temp.path().join(path), bytes).unwrap();
            }
            assert_eq!(rust_listing_certificate(temp.path()), expected, "{name}");
        }
    }

    /// The Rust listing certificate of the workspace's head revision: whether
    /// it is complete, and its failing rows.
    fn rust_head_listing_certificate(
        analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
    ) -> (bool, Vec<(String, String)>) {
        use crate::analyzer::store::{
            GenerationId, RUST_SOURCE_LISTING_DERIVATION_VERSION, WorkspaceId,
        };
        let store = analyzer.store().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: WorkspaceId(workspace_id),
            lang: "rust".into(),
            generation: GenerationId::from_persisted(generation),
            revision,
        };
        (
            store
                .rust_source_listing_complete(&snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
                .unwrap(),
            store
                .rust_source_listing_failures(&snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
                .unwrap()
                .unwrap(),
        )
    }

    #[test]
    #[hardwon("#10154: point updates without a listing cache never certified the Rust listing")]
    fn point_update_certifies_the_rust_listing_from_its_one_listing_read() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{
            FilesystemProject, Project, WorkspaceFileListingCache,
        };
        use std::sync::Arc;

        for cached in [false, true] {
            for oversized in [false, true] {
                let name = format!("cached={cached} oversized={oversized}");
                let temp = tempfile::tempdir().unwrap();
                std::fs::write(
                    temp.path().join("Cargo.toml"),
                    "[package]\nname = 'app'\nversion = '0.1.0'\n",
                )
                .unwrap();
                std::fs::create_dir(temp.path().join("src")).unwrap();
                std::fs::write(temp.path().join("src/lib.rs"), "pub fn app() {}\n").unwrap();
                if oversized {
                    std::fs::write(
                        temp.path().join("src/large.rs"),
                        vec![b' '; 1024 * 1024 + 1],
                    )
                    .unwrap();
                }
                // Without a listing cache, as `new_manual_persisted` builds it.
                let project = if cached {
                    let root = temp.path().canonicalize().unwrap();
                    let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
                    Arc::new(FilesystemProject::with_cached_listing(root, listing).unwrap())
                } else {
                    Arc::new(FilesystemProject::new(temp.path()).unwrap())
                };
                let analyzer =
                    WorkspaceAnalyzer::build_persisted(project.clone(), AnalyzerConfig::default())
                        .unwrap();
                // The edit moves no listing fact, so the build's certificate is
                // the from-scratch certificate the update must reproduce.
                let from_scratch = rust_head_listing_certificate(&analyzer);
                assert_eq!(from_scratch.0, !oversized, "{name}");

                let changed = brokk_bifrost_core::analyzer::model::ProjectFile::new(
                    temp.path().to_path_buf(),
                    "src/lib.rs",
                );
                std::fs::write(
                    changed.abs_path(),
                    "pub fn app() { let changed = 1; let _ = changed; }\n",
                )
                .unwrap();
                let before = project.workspace_file_listing_count();
                let analyzer = analyzer.update(&BTreeSet::from([changed]));
                assert_eq!(
                    project.workspace_file_listing_count() - before,
                    1,
                    "{name}: the update reads the listing once"
                );
                assert_eq!(
                    rust_head_listing_certificate(&analyzer),
                    from_scratch,
                    "{name}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#9737: a point update rescanned every Rust file, and an unavailable listing dropped earlier failures"
    )]
    fn incremental_rust_listing_certificate_recomputes_after_oversized_source() {
        let mut builder = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n")
            .file("src/lib.rs", "pub fn app() {}\n");
        for i in 0..24 {
            builder = builder.file(
                format!("src/extra_{i}.rs"),
                format!("pub fn extra_{i}() {{}}\n"),
            );
        }
        let fixture = builder.build();
        let cache = std::sync::Arc::new(
            brokk_bifrost_core::analyzer::project::WorkspaceFileListingCache::new(
                fixture.root().to_path_buf(),
            ),
        );
        let project = std::sync::Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::with_cached_listing(
                fixture.root(),
                std::sync::Arc::clone(&cache),
            )
            .unwrap(),
        );
        let mut analyzer = brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default()).unwrap();
        let certificate =
            |analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
                let store = analyzer.store().unwrap();
                let conn = store.read_conn().unwrap();
                let (workspace_id, generation, revision): (String, i64, i64) = conn
                .query_row(
                    "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
                let snapshot = WorkspaceSnapshotId {
                    workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(
                        workspace_id,
                    ),
                    lang: "rust".into(),
                    generation:
                        brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                            generation,
                        ),
                    revision,
                };
                let version =
                    brokk_bifrost_analysis::analyzer::store::RUST_SOURCE_LISTING_DERIVATION_VERSION;
                (
                    store
                        .rust_source_listing_complete(&snapshot, version)
                        .unwrap(),
                    store
                        .rust_source_listing_failures(&snapshot, version)
                        .unwrap()
                        .unwrap(),
                )
            };
        let from_scratch = || {
            let fresh_cache = std::sync::Arc::new(
                brokk_bifrost_core::analyzer::project::WorkspaceFileListingCache::new(
                    fixture.root().to_path_buf(),
                ),
            );
            let fresh_project = std::sync::Arc::new(
                brokk_bifrost_core::analyzer::project::FilesystemProject::with_cached_listing(
                    fixture.root(),
                    fresh_cache,
                )
                .unwrap(),
            );
            let fresh = brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_ephemeral_footgun(
                fresh_project,
                AnalyzerConfig::default(),
            )
            .unwrap();
            let (complete, failures) = certificate(&fresh);
            (
                complete,
                failures
                    .into_iter()
                    .map(|(path, _)| path)
                    .collect::<BTreeSet<_>>(),
            )
        };
        let assert_matches_fresh =
            |incremental: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
             expected: (bool, BTreeSet<String>)| {
                let (complete, failures) = certificate(incremental);
                let actual = (
                    complete,
                    failures
                        .into_iter()
                        .map(|(path, _)| path)
                        .collect::<BTreeSet<_>>(),
                );
                assert_eq!(actual, expected);
                assert_eq!(actual, from_scratch());
            };
        let broad = |analyzer: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
            analyzer.store().unwrap().read_conn().unwrap().query_row(
                "SELECT t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.crate_name='app' AND t.target_kind='lib'",
                [],
                |row| row.get::<_, bool>(0),
            ).unwrap()
        };
        assert_eq!(certificate(&analyzer), (true, vec![]));
        assert_matches_fresh(&analyzer, (true, BTreeSet::new()));
        assert!(broad(&analyzer));
        analyzer
            .store()
            .unwrap()
            .take_parsed_blob_membership_keys_for_test();
        let existing = fixture.file("src/lib.rs");
        existing
            .write("pub fn app() { let changed = 1; let _ = changed; }\n")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([existing]));
        assert_eq!(certificate(&analyzer), (true, vec![]));
        assert!(
            analyzer
                .store()
                .unwrap()
                .take_parsed_blob_membership_keys_for_test()
                <= 2,
            "point edit must not probe all published Rust blobs"
        );
        assert!(broad(&analyzer));
        let large = fixture.file("src/large.rs");
        std::fs::write(large.abs_path(), vec![b' '; 1024 * 1024 + 1]).unwrap();
        if !cache.update_path(&large, true) {
            cache.invalidate();
        }
        analyzer = analyzer.update(&BTreeSet::from([large.clone()]));
        assert_eq!(certificate(&analyzer).1.len(), 1);
        assert!(!certificate(&analyzer).0);
        assert_matches_fresh(
            &analyzer,
            (false, BTreeSet::from(["src/large.rs".to_string()])),
        );
        assert!(!broad(&analyzer));
        let existing = fixture.file("src/lib.rs");
        existing
            .write("pub fn app() { let second = 2; let _ = second; }\n")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([existing]));
        assert_eq!(certificate(&analyzer).1[0].0, "src/large.rs");
        assert_matches_fresh(
            &analyzer,
            (false, BTreeSet::from(["src/large.rs".to_string()])),
        );
        let refused = fixture.file("src/refused.rs");
        std::fs::write(refused.abs_path(), b"\0").unwrap();
        if !cache.update_path(&refused, true) {
            cache.invalidate();
        }
        analyzer = analyzer.update(&BTreeSet::from([refused]));
        assert_matches_fresh(
            &analyzer,
            (
                false,
                BTreeSet::from(["src/large.rs".to_string(), "src/refused.rs".to_string()]),
            ),
        );
        let removed = fixture.file("src/extra_23.rs");
        std::fs::remove_file(removed.abs_path()).unwrap();
        assert!(cache.update_path(&removed, false));
        analyzer = analyzer.update(&BTreeSet::from([removed]));
        assert_matches_fresh(
            &analyzer,
            (
                false,
                BTreeSet::from(["src/large.rs".to_string(), "src/refused.rs".to_string()]),
            ),
        );
        cache.invalidate();
        let existing = fixture.file("src/lib.rs");
        existing
            .write("pub fn app() { let unavailable = 4; let _ = unavailable; }\n")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([existing]));
        assert_eq!(certificate(&analyzer).1[0].0, "src/large.rs");
        assert_matches_fresh(
            &analyzer,
            (
                false,
                BTreeSet::from(["src/large.rs".to_string(), "src/refused.rs".to_string()]),
            ),
        );
        let store = analyzer.store().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        overwrite_rust_listing_certificate(
            store,
            &WorkspaceSnapshotId {
                workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace_id),
                lang: "rust".into(),
                generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                    generation,
                ),
                revision,
            },
            brokk_bifrost_analysis::analyzer::store::RUST_SOURCE_LISTING_DERIVATION_VERSION,
            vec![(String::new(), "listing unavailable".to_string())],
        );
        assert_eq!(
            certificate(&analyzer),
            (
                false,
                vec![(String::new(), "listing unavailable".to_string())]
            )
        );
        // The persisted unavailable row models a revision whose listing could
        // not be read; no fresh build produces it, so only the recovery
        // update below is compared with a fresh certificate.
        project.all_files().unwrap();
        let existing = fixture.file("src/lib.rs");
        existing
            .write("pub fn app() { let recovered = 5; let _ = recovered; }\n")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([existing]));
        assert!(
            certificate(&analyzer)
                .1
                .iter()
                .any(|(path, _)| path == "src/large.rs")
        );
        assert_matches_fresh(
            &analyzer,
            (
                false,
                BTreeSet::from(["src/large.rs".to_string(), "src/refused.rs".to_string()]),
            ),
        );
        assert!(!certificate(&analyzer).0);
        let store = analyzer.store().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let stale = WorkspaceSnapshotId {
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId(workspace_id),
            lang: "rust".into(),
            generation: brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(
                generation,
            ),
            revision,
        };
        let version =
            brokk_bifrost_analysis::analyzer::store::RUST_SOURCE_LISTING_DERIVATION_VERSION;
        overwrite_rust_listing_certificate(store, &stale, version - 1, vec![]);
        store.take_parsed_blob_membership_keys_for_test();
        let existing = fixture.file("src/lib.rs");
        existing
            .write("pub fn app() { let third = 3; let _ = third; }\n")
            .unwrap();
        analyzer = analyzer.update(&BTreeSet::from([existing]));
        assert_eq!(certificate(&analyzer).1[0].0, "src/large.rs");
        assert!(
            analyzer
                .store()
                .unwrap()
                .take_parsed_blob_membership_keys_for_test()
                >= 24,
            "stale derivation must recheck the full cached Rust listing"
        );
        assert_matches_fresh(
            &analyzer,
            (
                false,
                BTreeSet::from(["src/large.rs".to_string(), "src/refused.rs".to_string()]),
            ),
        );
        let refused = fixture.file("src/refused.rs");
        std::fs::write(refused.abs_path(), "pub fn repaired() {}\n").unwrap();
        analyzer = analyzer.update(&BTreeSet::from([refused]));
        assert_matches_fresh(
            &analyzer,
            (false, BTreeSet::from(["src/large.rs".to_string()])),
        );
        std::fs::write(large.abs_path(), "pub fn small() {}\n").unwrap();
        analyzer = analyzer.update(&BTreeSet::from([large.clone()]));
        assert_eq!(certificate(&analyzer), (true, vec![]));
        assert!(broad(&analyzer));
        assert_matches_fresh(&analyzer, (true, BTreeSet::new()));
        let added = fixture.file("src/new_large.rs");
        std::fs::write(added.abs_path(), vec![b' '; 1024 * 1024 + 1]).unwrap();
        if !cache.update_path(&added, true) {
            cache.invalidate();
        }
        analyzer = analyzer.update(&BTreeSet::from([added.clone()]));
        assert_eq!(certificate(&analyzer).1[0].0, "src/new_large.rs");
        assert!(!certificate(&analyzer).0);
        assert_matches_fresh(
            &analyzer,
            (false, BTreeSet::from(["src/new_large.rs".to_string()])),
        );
        assert!(!broad(&analyzer));
        std::fs::remove_file(added.abs_path()).unwrap();
        assert!(cache.update_path(&added, false));
        analyzer = analyzer.update(&BTreeSet::from([added]));
        assert_eq!(certificate(&analyzer), (true, vec![]));
        assert_matches_fresh(&analyzer, (true, BTreeSet::new()));
        assert!(broad(&analyzer));
    }

    #[test]
    #[hardwon("#9737: a stored listing-unavailable certificate was never recomputed")]
    fn incremental_rust_listing_certificate_recovers_when_listing_becomes_readable() {
        use brokk_bifrost_analysis::analyzer::store::{
            GenerationId, RUST_SOURCE_LISTING_DERIVATION_VERSION, WorkspaceId,
        };
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        use std::sync::Arc;

        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n")
            .file("src/lib.rs", "pub fn app() {}\n")
            .build();
        let cache = Arc::new(WorkspaceFileListingCache::new(fixture.root().to_path_buf()));
        let project = Arc::new(
            FilesystemProject::with_cached_listing(fixture.root(), Arc::clone(&cache)).unwrap(),
        );
        let analyzer = brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_ephemeral_footgun(
            project,
            AnalyzerConfig::default(),
        )
        .unwrap();
        let fresh = rust_head_listing_certificate(&analyzer);
        assert_eq!(fresh, (true, vec![]));
        // A certificate written while no listing was readable: an update that
        // took no listing and found no cache. A workspace update always passes
        // its listing, so the fixture rewrites the head's certificate instead.
        let store = analyzer.store().unwrap();
        let (workspace_id, generation, revision): (String, i64, i64) = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let head = WorkspaceSnapshotId {
            workspace_id: WorkspaceId(workspace_id),
            lang: "rust".into(),
            generation: GenerationId::from_persisted(generation),
            revision,
        };
        overwrite_rust_listing_certificate(
            store,
            &head,
            RUST_SOURCE_LISTING_DERIVATION_VERSION,
            vec![(String::new(), "listing unavailable".to_string())],
        );
        assert!(!rust_head_listing_certificate(&analyzer).0);

        // A later update has a readable listing and changes no Rust source.
        let readme = fixture.file("README.md");
        readme.write("no Rust change\n").unwrap();
        if !cache.update_path(&readme, true) {
            cache.invalidate();
        }
        let analyzer = analyzer.update(&BTreeSet::from([readme]));
        assert_eq!(
            rust_head_listing_certificate(&analyzer),
            fresh,
            "the readable listing recomputes the certificate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rust_listing_certificate_tracks_symlinks_and_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt;
        for (name, path, expected) in [
            ("rust symlink", std::ffi::OsString::from("linked.rs"), false),
            ("text symlink", std::ffi::OsString::from("linked.txt"), true),
            (
                "non-utf8 rust",
                std::ffi::OsString::from_vec(b"bad\xff.rs".to_vec()),
                false,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
            if name == "non-utf8 rust" {
                match std::fs::write(temp.path().join(path), "fn bad() {}\n") {
                    Ok(()) => {}
                    // APFS refuses non-UTF-8 names with EILSEQ (#10379); the
                    // symlink cases still run on such filesystems.
                    Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => continue,
                    Err(error) => panic!("{name}: {error:?}"),
                }
            } else {
                std::os::unix::fs::symlink("main.rs", temp.path().join(path)).unwrap();
            }
            assert_eq!(rust_listing_certificate(temp.path()), expected, "{name}");
        }
    }

    // A symlink is an omission, so this omits src/linked.RS: on a
    // case-insensitive volume rustc opens it for `mod linked;`.
    #[cfg(unix)]
    #[test]
    #[hardwon("#10469: an omitted .RS file passed the Rust listing certificate")]
    fn rust_listing_certificate_fails_for_an_omitted_upper_case_rs_file() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        std::os::unix::fs::symlink("main.rs", temp.path().join("linked.RS")).unwrap();
        assert!(!rust_listing_certificate(temp.path()));
    }

    #[cfg(unix)]
    fn scoped_directory_omission_case(case: &str) {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::FilesystemProject;
        let members = if case == "member" {
            "['app', 'other', 'source/*']"
        } else {
            "['app', 'other']"
        };
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                format!("[workspace]\nmembers={members}\nresolver='2'\n"),
            )
            .file("app/Cargo.toml", "[package]\nname='app'\nversion='0.1.0'\n")
            .file("app/src/lib.rs", "pub fn app() {}\n")
            .file(
                "other/Cargo.toml",
                "[package]\nname='other'\nversion='0.1.0'\n",
            )
            .file(
                "other/src/lib.rs",
                "#[path = \"../../source/real.rs\"] mod real;\n",
            )
            .file("shared/real.rs", "pub fn real() {}\n")
            .file("assets/data.txt", "asset\n")
            .build();
        // These platforms permit directory links without Windows privileges.
        // The whole test is skipped on Windows, like the #10321 regressions.
        std::os::unix::fs::symlink("assets", fixture.root().join("asset-link")).unwrap();
        std::os::unix::fs::symlink("shared", fixture.root().join("source")).unwrap();
        if case == "tests" {
            std::os::unix::fs::symlink("../shared", fixture.root().join("app/tests")).unwrap();
        }
        if case == "child" || case == "deep-assets" {
            let parent = if case == "child" {
                "app/tests"
            } else {
                "app/tests/data"
            };
            std::fs::create_dir_all(fixture.root().join(parent)).unwrap();
            std::os::unix::fs::symlink(
                fixture.root().join("shared"),
                fixture.root().join(parent).join("assets"),
            )
            .unwrap();
        }
        let project = std::sync::Arc::new(FilesystemProject::new(fixture.root()).unwrap());
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        let broad = |analyzer: &WorkspaceAnalyzer, name: &str| {
            analyzer.store().unwrap().read_conn().unwrap().query_row(
                "SELECT min(t.broad_complete) FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.crate_name=?1 AND t.target_kind='lib'",
                [name], |row| row.get::<_, bool>(0),
            ).unwrap()
        };
        assert!(!broad(&analyzer, "other"), "source-bearing link");
        assert_eq!(
            broad(&analyzer, "app"),
            case != "tests" && case != "member" && case != "child",
            "{case}"
        );
        if case == "warm" {
            std::fs::write(
                fixture.root().join("app/src/lib.rs"),
                "#[path = \"../../source/real.rs\"] mod real;\n",
            )
            .unwrap();
            let analyzer = analyzer.update(&BTreeSet::from([fixture.file("app/src/lib.rs")]));
            assert!(
                !broad(&analyzer, "app"),
                "moving a candidate under the omitted prefix withdraws a warm topology"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#10987: asset directory links withdrew unrelated crates")]
    fn directory_omissions_are_scoped_to_reachable_crates() {
        scoped_directory_omission_case("asset");
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#10987: symlinked tests directories can hide auto-discovered targets")]
    fn directory_omissions_cover_auto_discovered_tests() {
        scoped_directory_omission_case("tests");
        scoped_directory_omission_case("child");
        scoped_directory_omission_case("deep-assets");
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#10987: member globs can reach an omitted directory")]
    fn directory_omissions_cover_member_globs() {
        scoped_directory_omission_case("member");
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#10987: moving a route under an omitted prefix must withdraw warm completeness")]
    fn directory_omissions_invalidate_moved_routes() {
        scoped_directory_omission_case("warm");
    }

    #[cfg(unix)]
    #[test]
    fn directory_omissions_cover_the_implicit_library_root() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::FilesystemProject;
        // Cargo discovers src/lib.rs whatever autobins says, so an omitted src
        // link hides a whole library target that no module walk can see.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\nautobins=false\n[[bin]]\nname='cli'\npath='cli/main.rs'\n",
            )
            .file("cli/main.rs", "fn main() {}\n")
            .file("real/lib.rs", "pub fn lib() {}\n")
            .build();
        std::os::unix::fs::symlink("real", fixture.root().join("src")).unwrap();
        let project = std::sync::Arc::new(FilesystemProject::new(fixture.root()).unwrap());
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        let complete: Vec<(String, String, bool)> = {
            let conn = analyzer.store().unwrap().read_conn().unwrap();
            let mut statement = conn
                .prepare(
                    "SELECT t.crate_name, t.target_kind, t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL ORDER BY 1, 2",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        // The linked directory's lib.rs is also listed through its real path,
        // as a detached file outside any package; only the package's targets
        // are in question.
        let package = complete
            .iter()
            .filter(|(_, kind, _)| kind != "detached")
            .collect::<Vec<_>>();
        assert!(
            !package.is_empty(),
            "the explicit binary has a topology: {complete:?}"
        );
        assert!(
            package.iter().all(|(_, _, broad)| !broad),
            "an omitted src link must keep the package incomplete: {complete:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#10321: a directory symlink passed the Rust listing certificate")]
    fn rust_listing_certificate_fails_for_directory_and_unreadable_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).expect("workspace root");
        let root = root.canonicalize().expect("canonical root");
        write(
            temp.path(),
            "outside/Cargo.toml",
            "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
        );
        write(temp.path(), "outside/src/lib.rs", "pub struct Escaped;\n");
        symlink(temp.path().join("outside"), root.join("linked")).expect("dependency symlink");
        write(
            &root,
            "consumer/Cargo.toml",
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nlinked = { path = \"../linked\" }\n",
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");

        write(
            &root,
            "bad_lib/Cargo.toml",
            "[package]\nname = \"bad-lib\"\nversion = \"0.1.0\"\n[lib]\npath = \"../linked/src/lib.rs\"\n",
        );
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = ['consumer', 'bad_lib']\n",
        );
        write(&root, "bad_lib/src/lib.rs", "pub fn fallback() {}\n");
        assert!(!rust_listing_certificate(&root));
        with_certified_rust_routes(&root, |rust| {
            let routes = rust.file_routes(&consumer, None).unwrap();
            assert!(!routes.is_complete());
            assert_eq!(routes.resolve_module_package(&consumer, "linked"), None);
            let escaped = ProjectFile::new(root.clone(), "linked/src/lib.rs");
            assert!(
                rust.file_routes(&escaped, None)
                    .unwrap()
                    .target_roots(&escaped)
                    .is_empty()
            );
        });

        for (name, target, expected) in [
            ("directory symlink", "shared", false),
            ("unreadable symlink", "missing", false),
            ("symlink to a non-Rust file", "data.txt", true),
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
            std::fs::write(temp.path().join("data.txt"), "data\n").unwrap();
            std::fs::create_dir(temp.path().join("shared")).unwrap();
            std::fs::write(temp.path().join("shared/real.rs"), "fn real() {}\n").unwrap();
            std::os::unix::fs::symlink(target, temp.path().join("link")).unwrap();
            assert_eq!(rust_listing_certificate(temp.path()), expected, "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#10321: deleting a symlink's target left the Rust listing certified")]
    #[hardwon("#10321: a listing-only change rewrote the certificate of an existing revision")]
    fn incremental_rust_listing_certificate_agrees_for_directory_symlinks() {
        use brokk_bifrost_analysis::analyzer::store::{
            GenerationId, RUST_SOURCE_LISTING_DERIVATION_VERSION, WorkspaceId,
        };
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n")
            .file("src/lib.rs", "#[path = \"link/real.rs\"]\nmod real;\n")
            .file("src/data.txt", "data\n")
            .file("shared/real.rs", "pub fn real() {}\n")
            .file(".gitignore", "src/outer/\n")
            .build();
        let repository = brokk_bifrost_core::gitblob::test_repo::init_repo(fixture.root());
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repository, "initial");
        let cache =
            std::sync::Arc::new(WorkspaceFileListingCache::new(fixture.root().to_path_buf()));
        let project = std::sync::Arc::new(
            FilesystemProject::with_cached_listing(fixture.root(), std::sync::Arc::clone(&cache))
                .unwrap(),
        );
        let mut analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        // The certificate, its failing paths and the library's broad_complete.
        let state = |analyzer: &WorkspaceAnalyzer| {
            let store = analyzer.store().unwrap();
            let conn = store.read_conn().unwrap();
            let (workspace_id, generation, revision): (String, i64, i64) = conn
                .query_row(
                    "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            let snapshot = WorkspaceSnapshotId {
                workspace_id: WorkspaceId(workspace_id),
                lang: "rust".into(),
                generation: GenerationId::from_persisted(generation),
                revision,
            };
            let broad = conn
                .query_row(
                    "SELECT t.broad_complete FROM rust_crate_versions v JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.crate_name='app' AND t.target_kind='lib'",
                    [],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap();
            (
                store
                    .rust_source_listing_complete(&snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
                    .unwrap(),
                store
                    .rust_source_listing_failures(&snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
                    .unwrap()
                    .unwrap()
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .map(|(path, reason)| {
                        if path == "src/data.link" {
                            let expected = if fixture.root().join("src/data.txt").is_dir() {
                                "SymlinkToDirectory"
                            } else {
                                "UnreadableSymlink"
                            };
                            assert!(reason.ends_with(expected), "target kind reason: {reason}");
                        }
                        path
                    })
                    .collect::<BTreeSet<_>>(),
                broad,
            )
        };
        let from_scratch = || {
            let fresh_cache =
                std::sync::Arc::new(WorkspaceFileListingCache::new(fixture.root().to_path_buf()));
            let project = std::sync::Arc::new(
                FilesystemProject::with_cached_listing(fixture.root(), fresh_cache).unwrap(),
            );
            state(
                &WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                    .unwrap(),
            )
        };
        let update = |analyzer: WorkspaceAnalyzer, path: &str| {
            if !project.update_cached_listing_for_path(std::path::Path::new(path)) {
                project.invalidate_cached_file_listing();
            }
            analyzer.update(&BTreeSet::from([fixture.file(path)]))
        };
        let revision = |analyzer: &WorkspaceAnalyzer| {
            analyzer
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        };
        // The certificate stored at one revision, read at that revision.
        let certificate_at = |analyzer: &WorkspaceAnalyzer, revision: i64| {
            let store = analyzer.store().unwrap();
            let (workspace_id, generation): (String, i64) = store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT workspace_id,generation FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let snapshot = WorkspaceSnapshotId {
                workspace_id: WorkspaceId(workspace_id),
                lang: "rust".into(),
                generation: GenerationId::from_persisted(generation),
                revision,
            };
            (
                store
                    .rust_source_listing_complete(&snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
                    .unwrap(),
                store
                    .rust_source_listing_failures(&snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
                    .unwrap(),
            )
        };
        // The Rust revision the analyzer itself selects, which routes the next
        // update and binds the answers it retains.
        let selected_revision = |analyzer: &WorkspaceAnalyzer| {
            analyzer
                .analyzer()
                .selected_workspace_snapshots_for_reads()
                .unwrap()["rust"]
                .revision
        };
        let before = revision(&analyzer);
        fixture
            .file("README.md")
            .write("changed documentation")
            .unwrap();
        analyzer = update(analyzer, "README.md");
        assert_eq!(revision(&analyzer), before, "README must not update Rust");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        let root = fixture.root();
        std::os::unix::fs::symlink("data.txt", root.join("src/data.link")).unwrap();
        analyzer = update(analyzer, "src/data.link");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        assert_eq!(state(&analyzer), from_scratch());
        std::fs::remove_file(root.join("src/data.txt")).unwrap();
        analyzer = update(analyzer, "src/data.txt");
        assert!(
            !state(&analyzer).0,
            "target deletion must invalidate certificate"
        );
        assert_eq!(
            state(&analyzer),
            from_scratch(),
            "target deletion freshness and routing"
        );
        std::fs::write(root.join("src/data.txt"), "restored").unwrap();
        analyzer = update(analyzer, "src/data.txt");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        assert_eq!(state(&analyzer), from_scratch(), "target recreation");
        std::fs::remove_file(root.join("src/data.txt")).unwrap();
        std::fs::create_dir(root.join("src/data.txt")).unwrap();
        analyzer = update(analyzer, "src/data.txt");
        assert!(
            !state(&analyzer).0,
            "directory target must invalidate certificate"
        );
        assert_eq!(
            state(&analyzer),
            from_scratch(),
            "directory target replacement"
        );
        std::fs::remove_dir(root.join("src/data.txt")).unwrap();
        std::fs::write(root.join("src/data.txt"), "restored").unwrap();
        analyzer = update(analyzer, "src/data.txt");
        assert_eq!(state(&analyzer), from_scratch());
        // A directory symlink with no extension changes no file version, only
        // the listing. A revision's certificate never changes, so the update
        // opens a new revision for the failing certificate and the analyzer
        // selects it.
        let certified = revision(&analyzer);
        let certified_certificate = certificate_at(&analyzer, certified);
        assert_eq!(certified_certificate, (true, Some(Vec::new())));
        assert_eq!(selected_revision(&analyzer), certified);
        std::os::unix::fs::symlink("../shared", root.join("src/link")).unwrap();
        analyzer = update(analyzer, "src/link");
        assert_eq!(
            revision(&analyzer),
            certified + 1,
            "a listing-only change must open a revision"
        );
        assert_eq!(selected_revision(&analyzer), certified + 1);
        assert_eq!(
            certificate_at(&analyzer, certified),
            certified_certificate,
            "the earlier revision's certificate must not change"
        );
        let failed = certificate_at(&analyzer, certified + 1);
        assert!(!failed.0);
        assert_eq!(
            failed
                .1
                .unwrap()
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>(),
            ["src/link"]
        );
        assert_eq!(
            state(&analyzer),
            (false, BTreeSet::from(["src/link".to_string()]), false)
        );
        assert_eq!(state(&analyzer), from_scratch());
        std::fs::remove_file(root.join("src/link")).unwrap();
        analyzer = update(analyzer, "src/link");
        assert_eq!(revision(&analyzer), certified + 2);
        assert_eq!(selected_revision(&analyzer), certified + 2);
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        assert_eq!(state(&analyzer), from_scratch());
        std::os::unix::fs::symlink("missing", root.join("src/link")).unwrap();
        analyzer = update(analyzer, "src/link");
        assert_eq!(
            state(&analyzer),
            (false, BTreeSet::from(["src/link".to_string()]), false)
        );
        assert_eq!(state(&analyzer), from_scratch());
        std::fs::remove_file(root.join("src/link")).unwrap();
        analyzer = update(analyzer, "src/link");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        assert_eq!(state(&analyzer), from_scratch());
        // The target sits in an ignored directory, so no listed file is below
        // `src/outer` and only the symlink revalidation can see it go away.
        std::fs::create_dir_all(root.join("src/outer")).unwrap();
        std::fs::write(root.join("src/outer/leaf.txt"), "leaf").unwrap();
        std::os::unix::fs::symlink("outer/leaf.txt", root.join("src/outer.link")).unwrap();
        analyzer = update(analyzer, "src/outer.link");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        assert_eq!(state(&analyzer), from_scratch(), "link into ignored dir");
        std::fs::remove_dir_all(root.join("src/outer")).unwrap();
        analyzer = update(analyzer, "src/outer");
        assert!(
            !state(&analyzer).0,
            "ancestor removal must invalidate certificate"
        );
        assert_eq!(state(&analyzer), from_scratch(), "ancestor removal");
        std::fs::create_dir_all(root.join("src/outer")).unwrap();
        std::fs::write(root.join("src/outer/leaf.txt"), "leaf").unwrap();
        analyzer = update(analyzer, "src/outer");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        assert_eq!(state(&analyzer), from_scratch(), "ancestor recreation");
        std::fs::rename(root.join("src/outer"), root.join("src/moved")).unwrap();
        analyzer = update(analyzer, "src/outer");
        assert!(
            !state(&analyzer).0,
            "ancestor rename must invalidate certificate"
        );
        assert_eq!(state(&analyzer), from_scratch(), "ancestor rename");
        std::fs::remove_file(root.join("src/outer.link")).unwrap();
        analyzer = update(analyzer, "src/outer.link");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        std::os::unix::fs::symlink("data.txt", root.join("src/tracked.link")).unwrap();
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repository, "track link");
        analyzer = update(analyzer, "src/tracked.link");
        std::fs::remove_file(root.join("src/tracked.link")).unwrap();
        std::os::unix::fs::symlink("../shared", root.join("src/tracked.link")).unwrap();
        analyzer = update(analyzer, "src/tracked.link");
        assert!(
            !state(&analyzer).0,
            "dirty tracked directory link must fail"
        );
        assert_eq!(state(&analyzer), from_scratch(), "dirty tracked symlink");
        std::fs::remove_file(root.join("src/tracked.link")).unwrap();
        std::fs::create_dir_all(root.join("src/link")).unwrap();
        fixture
            .file("src/link/real.rs")
            .write("pub fn real() {}\n")
            .unwrap();
        analyzer = update(analyzer, "src/link/real.rs");
        assert_eq!(state(&analyzer), (true, BTreeSet::new(), true));
        assert_eq!(state(&analyzer), from_scratch(), "placed module control");
    }

    #[test]
    #[hardwon("#10321: a point update opened an extra revision for its certificate")]
    fn point_update_certifies_only_its_last_revision() {
        use brokk_bifrost_analysis::analyzer::store::{
            GenerationId, RUST_SOURCE_LISTING_DERIVATION_VERSION, WorkspaceId,
        };
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n")
            .file("src/lib.rs", "mod a;\nmod b;\n")
            .file("src/a.rs", "pub fn a() {}\n")
            .file("src/b.rs", "pub fn b() {}\n")
            .build();
        let repository = brokk_bifrost_core::gitblob::test_repo::init_repo(fixture.root());
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repository, "initial");
        let cache =
            std::sync::Arc::new(WorkspaceFileListingCache::new(fixture.root().to_path_buf()));
        let project = std::sync::Arc::new(
            FilesystemProject::with_cached_listing(fixture.root(), cache).unwrap(),
        );
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        let head = |analyzer: &WorkspaceAnalyzer| -> WorkspaceSnapshotId {
            let conn = analyzer.store().unwrap().read_conn().unwrap();
            let (workspace_id, generation, revision): (String, i64, i64) = conn
                .query_row(
                    "SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            WorkspaceSnapshotId {
                workspace_id: WorkspaceId(workspace_id),
                lang: "rust".into(),
                generation: GenerationId::from_persisted(generation),
                revision,
            }
        };
        // The certificate stored at a revision: None when it holds none.
        let certificate = |analyzer: &WorkspaceAnalyzer, snapshot: &WorkspaceSnapshotId| {
            analyzer
                .store()
                .unwrap()
                .rust_source_listing_failures(snapshot, RUST_SOURCE_LISTING_DERIVATION_VERSION)
                .unwrap()
        };
        let start = head(&analyzer);
        assert_eq!(certificate(&analyzer, &start), Some(vec![]));

        // Two files publish at two revisions. Only the second holds both, so
        // only it carries the certificate; the first is never certified.
        let (a, b) = (fixture.file("src/a.rs"), fixture.file("src/b.rs"));
        a.write("pub fn a2() {}\n").unwrap();
        b.write("pub fn b2() {}\n").unwrap();
        let analyzer = analyzer.update(&BTreeSet::from([a.clone(), b.clone()]));
        let end = head(&analyzer);
        assert_eq!(end.revision, start.revision + 2, "one revision per file");
        let middle = WorkspaceSnapshotId {
            revision: start.revision + 1,
            ..end.clone()
        };
        assert_eq!(
            certificate(&analyzer, &middle),
            None,
            "intermediate revision"
        );
        assert_eq!(certificate(&analyzer, &end), Some(vec![]), "final revision");
        assert_eq!(
            analyzer
                .analyzer()
                .selected_workspace_snapshots_for_reads()
                .unwrap()["rust"],
            end
        );
        let fresh = {
            let cache =
                std::sync::Arc::new(WorkspaceFileListingCache::new(fixture.root().to_path_buf()));
            let project = std::sync::Arc::new(
                FilesystemProject::with_cached_listing(fixture.root(), cache).unwrap(),
            );
            let fresh =
                WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                    .unwrap();
            let snapshot = head(&fresh);
            certificate(&fresh, &snapshot)
        };
        assert_eq!(
            certificate(&analyzer, &end),
            fresh,
            "agrees with a fresh build"
        );

        // One changed file ends at one revision, certified.
        a.write("pub fn a3() {}\n").unwrap();
        let analyzer = analyzer.update(&BTreeSet::from([a.clone()]));
        let one = head(&analyzer);
        assert_eq!(one.revision, end.revision + 1);
        assert_eq!(certificate(&analyzer, &one), Some(vec![]));

        // A file rewritten with the same bytes changes no version and
        // certifies an unchanged listing, so no revision opens.
        a.write("pub fn a3() {}\n").unwrap();
        let analyzer = analyzer.update(&BTreeSet::from([a]));
        assert_eq!(head(&analyzer), one);
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#10321: a listing-only change left retained route answers complete")]
    fn listing_only_change_does_not_reuse_retained_selected_units_known() {
        use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_rust_analysis::analyzer::rust::route_kinds::RustSelectedUnitsKnown;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind;
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n")
            .file("src/lib.rs", "pub fn app() {}\n")
            .file("shared/real.rs", "pub fn real() {}\n")
            .build();
        let repository = brokk_bifrost_core::gitblob::test_repo::init_repo(fixture.root());
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repository, "initial");
        let cache =
            std::sync::Arc::new(WorkspaceFileListingCache::new(fixture.root().to_path_buf()));
        let project = std::sync::Arc::new(
            FilesystemProject::with_cached_listing(fixture.root(), std::sync::Arc::clone(&cache))
                .unwrap(),
        );
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        assert_eq!(
            route_question_availability(&analyzer, "src/lib.rs", "app", &host),
            all_route_questions(Some(true))
        );
        let first = host.counters(RustSelectedUnitsKnown::ID);
        assert!(first.recomputed > 0);
        // No file version changes: only the listing's omission set does.
        std::os::unix::fs::symlink("../shared", fixture.root().join("src/bin")).unwrap();
        if !project.update_cached_listing_for_path(std::path::Path::new("src/bin")) {
            project.invalidate_cached_file_listing();
        }
        let analyzer = analyzer.update(&BTreeSet::from([fixture.file("src/bin")]));
        assert!(!selected_broad_complete(&analyzer));
        assert_eq!(
            route_question_availability(&analyzer, "src/lib.rs", "app", &host),
            all_route_questions(Some(false)),
            "a retained complete answer must not outlive the certificate"
        );
        assert!(
            host.counters(RustSelectedUnitsKnown::ID).recomputed > first.recomputed,
            "the new revision must rebind the answer"
        );
    }

    #[test]
    fn rust_listing_certificate_ignores_gitignored_rust_without_repository() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(temp.path().join(".gitignore"), "ignored.rs\n").unwrap();
        std::fs::write(temp.path().join("ignored.rs"), "fn ignored() {}\n").unwrap();
        assert!(rust_listing_certificate(temp.path()));
    }

    #[test]
    fn rust_listing_certificate_ignores_gitignored_rust_in_repository() {
        use brokk_bifrost_core::gitblob::test_repo::{commit_all, init_repo};
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(temp.path().join(".gitignore"), "ignored.rs\n").unwrap();
        let repository = init_repo(temp.path());
        commit_all(&repository, "initial");
        std::fs::write(temp.path().join("ignored.rs"), "fn ignored() {}\n").unwrap();
        assert!(rust_listing_certificate(temp.path()));
    }

    #[cfg(unix)]
    #[test]
    fn rust_listing_construction_error_publishes_no_certificate() {
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, PartialWorkspaceListing};
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use std::os::unix::fs::PermissionsExt;

        // Root can traverse directories with mode 000, so this control cannot run as root.
        if std::process::Command::new("id")
            .arg("-u")
            .output()
            .unwrap()
            .stdout
            == b"0\n"
        {
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let unreadable = temp.path().join("unreadable");
        std::fs::create_dir(&unreadable).unwrap();
        std::fs::write(unreadable.join("nested.rs"), "fn nested() {}\n").unwrap();
        let store =
            AnalyzerStore::open_for_workspace(temp.path(), &RetentionBudget::new(1_000_000))
                .unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = FilesystemProject::new(temp.path());
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = match result {
            Ok(_) => panic!("unreadable directory must refuse project construction"),
            Err(error) => error,
        };
        assert!(
            PartialWorkspaceListing::files_of(&error).is_some(),
            "{error:?}"
        );
        let workspace_id = crate::analyzer::store::WorkspaceId::for_root(temp.path());
        let count: i64 = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM rust_source_listing_certificates WHERE workspace_id = ?1",
                [workspace_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn cargo_configuration_patches_route_from_the_workspace_root_upward() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "ws/Cargo.toml",
            "[package]\nname = \"ws\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [workspace]\nmembers = [\"app\"]\n\n\
             [patch.crates-io]\npatched = { path = \"manifest-patched\" }\n",
        );
        write(&root, "ws/src/lib.rs", "pub struct Ws;\n");
        write(
            &root,
            "ws/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\npatched = \"1\"\nother = \"1\"\nignored = \"1\"\n",
        );
        write(&root, "ws/app/src/lib.rs", "pub struct App;\n");
        write(
            &root,
            "ws/.cargo/config.toml",
            "[patch.crates-io]\npatched = { path = \"config-patched\" }\n",
        );
        write(
            &root,
            ".cargo/config.toml",
            "[patch.crates-io]\nother = { path = \"ws/other\" }\n",
        );
        write(
            &root,
            "ws/app/.cargo/config.toml",
            "[patch.crates-io]\nignored = { path = \"../ignored\" }\n",
        );
        let mut libraries = vec![
            app_library(&root),
            ProjectFile::new(root.clone(), "ws/src/lib.rs"),
        ];
        for (directory, package) in [
            ("ws/manifest-patched", "patched"),
            ("ws/config-patched", "patched"),
            ("ws/other", "other"),
            ("ws/ignored", "ignored"),
        ] {
            write(
                &root,
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{package}\"\nversion = \"1.0.0\"\nedition = \"2021\"\n"
                ),
            );
            write(&root, &format!("{directory}/src/lib.rs"), "pub struct P;\n");
            libraries.push(ProjectFile::new(
                root.clone(),
                format!("{directory}/src/lib.rs"),
            ));
        }
        fn app_library(root: &std::path::Path) -> ProjectFile {
            ProjectFile::new(root.to_path_buf(), "ws/app/src/lib.rs")
        }
        let app = app_library(&root);
        with_certified_rust_routes(&root, |rust| {
            let routes = rust.file_routes(&app, None).unwrap();

            assert_eq!(
                routes.resolve_crate_root_file(&app, "patched"),
                Some(ProjectFile::new(
                    root.clone(),
                    "ws/config-patched/src/lib.rs"
                )),
                "the configuration patch replaces the manifest patch of the same name"
            );
            assert_eq!(
                routes.resolve_crate_root_file(&app, "other"),
                Some(ProjectFile::new(root.clone(), "ws/other/src/lib.rs")),
                "a shallower configuration applies, relative to its own directory"
            );
            assert_eq!(
                routes.resolve_crate_root_file(&app, "ignored"),
                None,
                "a member directory's configuration does not apply to its workspace"
            );
        });
    }
    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks patch selection requires both the matching source and a compatible version."
    )]
    fn patched_dependencies_require_matching_source_and_semver() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[workspace]
members = ["app", "shared-v1", "future-v1", "git-wrong"]
resolver = "2"

[patch.crates-io]
shared = { path = "shared-v1" }
future = { package = "future-shared", path = "future-v1" }

[patch."https://wrong.example/repository"]
git_shared = { package = "git-shared", path = "git-wrong" }
"#,
        );
        for (directory, package, version) in [
            ("shared-v1", "shared", "1.4.0"),
            ("future-v1", "future-shared", "1.9.0"),
            ("git-wrong", "git-shared", "3.0.0"),
        ] {
            write(
                &root,
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{package}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{directory}/src/lib.rs"),
                "pub struct Patched;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
shared = "^1.2"
future = { package = "future-shared", version = "^2" }
git_shared = { package = "git-shared", git = "https://good.example/repository" }
"#,
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let shared = ProjectFile::new(root.clone(), "shared-v1/src/lib.rs");
        let _future = ProjectFile::new(root.clone(), "future-v1/src/lib.rs");
        let _wrong_git = ProjectFile::new(root.clone(), "git-wrong/src/lib.rs");
        with_certified_rust_routes(&root, |rust| {
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "shared"),
                Some(shared),
                "a crates.io patch with an applicable version is a proven route"
            );
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "future"),
                None,
                "an incompatible patched package version must fail closed"
            );
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "git_shared"),
                None,
                "a patch for a different source must not satisfy the dependency"
            );
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks inherited package version participates in patch semver matching."
    )]
    fn patched_dependency_uses_workspace_inherited_package_version() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[workspace]
members = ["app", "patched"]
resolver = "2"

[workspace.package]
version = "1.4.0"

[patch.crates-io]
patched = { path = "patched" }
"#,
        );
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\npatched = \"^1.2\"\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");
        write(
            &root,
            "patched/Cargo.toml",
            "[package]\nname = \"patched\"\nversion.workspace = true\n",
        );
        write(&root, "patched/src/lib.rs", "pub struct Patched;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let patched = ProjectFile::new(root.clone(), "patched/src/lib.rs");
        with_certified_rust_routes(&root, |rust| {
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "patched"),
                Some(patched),
                "a path patch remains applicable when its package version is inherited"
            );
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks standalone package patch tables route dependencies without a workspace root."
    )]
    fn standalone_package_root_applies_its_patch_table() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
patched = "^1"

[patch.crates-io]
patched = { path = "patched" }
"#,
        );
        write(&root, "src/lib.rs", "pub struct App;\n");
        write(
            &root,
            "patched/Cargo.toml",
            "[package]\nname = \"patched\"\nversion = \"1.2.0\"\nedition = \"2021\"\n",
        );
        write(&root, "patched/src/lib.rs", "pub struct Patched;\n");

        let app = ProjectFile::new(root.clone(), "src/lib.rs");
        let patched = ProjectFile::new(root.clone(), "patched/src/lib.rs");
        with_certified_rust_routes(&root, |rust| {
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "patched"),
                Some(patched)
            );
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks semver filtering can make an alias unique and multiple compatible candidates remain ambiguous."
    )]
    fn patch_aliases_filter_by_semver_before_unique_selection() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[workspace]
members = ["app", "shared-*", "ambiguous-*"]
resolver = "2"

[patch.crates-io]
shared_old = { package = "shared", path = "shared-old" }
shared_new = { package = "shared", path = "shared-new" }
ambiguous_left = { package = "ambiguous", path = "ambiguous-left" }
ambiguous_right = { package = "ambiguous", path = "ambiguous-right" }
"#,
        );
        for (directory, package, version) in [
            ("shared-old", "shared", "1.9.0"),
            ("shared-new", "shared", "2.1.0"),
            ("ambiguous-left", "ambiguous", "3.1.0"),
            ("ambiguous-right", "ambiguous", "3.2.0"),
        ] {
            write(
                &root,
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{package}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{directory}/src/lib.rs"),
                "pub struct Item;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nshared = \"^2\"\nambiguous = \"^3\"\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let shared = ProjectFile::new(root.clone(), "shared-new/src/lib.rs");
        with_certified_rust_routes(&root, |rust| {
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "shared"),
                Some(shared),
                "an incompatible first alias must not hide the unique compatible patch"
            );
            assert_eq!(
                rust.file_routes(&app, None)
                    .unwrap()
                    .resolve_crate_root_file(&app, "ambiguous"),
                None,
                "multiple compatible patch destinations must fail closed"
            );
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks #[path] resolution uses physical parents versus relocated inline-module bases, with decoys."
    )]
    fn path_attributes_distinguish_physical_file_and_inline_module_bases() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        );
        write(&root, "src/lib.rs", "mod outer;\n");
        write(
            &root,
            "src/outer.rs",
            "#[path = \"top.rs\"]\nmod top;\n\n#[path = \"relocated\"]\nmod inline {\n    #[path = \"mapped.rs\"]\n    mod mapped;\n    mod ordinary;\n}\n",
        );
        write(&root, "src/top.rs", "pub struct Top;\n");
        write(&root, "src/relocated/mapped.rs", "pub struct Mapped;\n");
        write(&root, "src/relocated/ordinary.rs", "pub struct Ordinary;\n");
        write(&root, "src/outer/top.rs", "pub struct WrongTop;\n");
        write(
            &root,
            "src/outer/inline/mapped.rs",
            "pub struct WrongMapped;\n",
        );

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let _outer = ProjectFile::new(root.clone(), "src/outer.rs");
        let top = ProjectFile::new(root.clone(), "src/top.rs");
        let mapped = ProjectFile::new(root.clone(), "src/relocated/mapped.rs");
        let ordinary = ProjectFile::new(root.clone(), "src/relocated/ordinary.rs");
        let wrong_top = ProjectFile::new(root.clone(), "src/outer/top.rs");
        let wrong_mapped = ProjectFile::new(root.clone(), "src/outer/inline/mapped.rs");
        with_certified_rust_routes(&root, |rust| {
            for expected in [top, mapped, ordinary] {
                assert_eq!(
                    rust.file_routes(&expected, None)
                        .unwrap()
                        .target_roots(&expected),
                    std::slice::from_ref(&library),
                    "{} should follow the physical #[path] module tree",
                    expected.rel_path().display()
                );
            }
            for decoy in [wrong_top, wrong_mapped] {
                assert!(
                    rust.file_routes(&decoy, None)
                        .unwrap()
                        .target_roots(&decoy)
                        .is_empty(),
                    "{} uses the obsolete logical base",
                    decoy.rel_path().display()
                );
            }
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks raw and cooked Rust #[path] literals decode to the same target path."
    )]
    fn path_attributes_decode_raw_and_cooked_string_literals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        );
        write(
            &root,
            "src/lib.rs",
            r##"#[path = r#"nested/raw.rs"#]
mod raw;
#[path = "nested\x2fcooked.rs"]
mod cooked;
"##,
        );
        write(&root, "src/nested/raw.rs", "pub struct Raw;\n");
        write(&root, "src/nested/cooked.rs", "pub struct Cooked;\n");

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let raw = ProjectFile::new(root.clone(), "src/nested/raw.rs");
        let cooked = ProjectFile::new(root.clone(), "src/nested/cooked.rs");
        with_certified_rust_routes(&root, |rust| {
            for expected in [raw, cooked] {
                assert_eq!(
                    rust.file_routes(&expected, None)
                        .unwrap()
                        .target_roots(&expected),
                    std::slice::from_ref(&library),
                    "{} should follow the decoded #[path] value",
                    expected.rel_path().display()
                );
            }
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks edition-2015 manual target discovery rules while preserving the library target."
    )]
    fn edition_2015_manual_targets_disable_implicit_auto_discovery() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"legacy\"\nversion = \"0.1.0\"\n\n[[bin]]\nname = \"manual\"\npath = \"cmd/manual.rs\"\n",
        );
        write(&root, "cmd/manual.rs", "fn main() {}\n");
        write(&root, "src/lib.rs", "pub struct ImplicitLibrary;\n");
        write(&root, "src/main.rs", "fn main() {}\n");
        write(&root, "examples/implicit.rs", "fn main() {}\n");

        let manual = ProjectFile::new(root.clone(), "cmd/manual.rs");
        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let main = ProjectFile::new(root.clone(), "src/main.rs");
        let example = ProjectFile::new(root.clone(), "examples/implicit.rs");
        with_certified_rust_routes(&root, |rust| {
            assert_eq!(
                rust.file_routes(&manual, None)
                    .unwrap()
                    .target_roots(&manual),
                std::slice::from_ref(&manual)
            );
            // Corrected 2026-09-22, measured against Cargo 1.96 rather than read
            // from the documentation. This package reports targets
            // `[legacy: lib (lib.rs), legacy-cli: bin (cli.rs)]` under
            // `cargo metadata --no-deps`: the legacy 2015 rule drops the implicit
            // `src/main.rs` binary and the implicit example, and does not touch the
            // library. `src/lib.rs` is the package's library in every edition unless
            // `[lib]` names another path or `autolib = false`.
            assert_eq!(
                rust.file_routes(&library, None)
                    .unwrap()
                    .target_roots(&library),
                std::slice::from_ref(&library),
                "the library is discovered whatever else a 2015 manifest declares"
            );
            for implicit in [main, example] {
                assert!(
                    rust.file_routes(&implicit, None)
                        .unwrap()
                        .target_roots(&implicit)
                        .is_empty(),
                    "{} must not be auto-discovered for a legacy manifest with a manual target",
                    implicit.rel_path().display()
                );
            }
        });
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Checks inherited 2021 edition auto targets and explicit test=false target mode on a shared file."
    )]
    fn inherited_modern_edition_preserves_auto_targets_and_same_file_target_modes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"dev-dep\"]\nresolver = \"2\"\n\n[workspace.package]\nedition = \"2021\"\n",
        );
        write(
            &root,
            "dev-dep/Cargo.toml",
            "[package]\nname = \"dev-dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "dev-dep/src/lib.rs", "pub struct Dev;\n");
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n\n[[bin]]\nname = \"manual-main\"\npath = \"src/main.rs\"\ntest = false\n\n[dev-dependencies]\ndev_dep = { package = \"dev-dep\", path = \"../dev-dep\" }\n",
        );
        write(&root, "app/src/main.rs", "fn main() {}\n");
        write(&root, "app/examples/implicit.rs", "fn main() {}\n");

        let dependency = ProjectFile::new(root.clone(), "dev-dep/src/lib.rs");
        let main = ProjectFile::new(root.clone(), "app/src/main.rs");
        let example = ProjectFile::new(root.clone(), "app/examples/implicit.rs");
        with_certified_rust_routes(&root, |rust| {
            assert!(rust.file_routes(&main, None).unwrap().is_complete());
            assert_eq!(
                rust.file_routes(&example, None)
                    .unwrap()
                    .target_roots(&example),
                std::slice::from_ref(&example)
            );
            assert_eq!(
                rust.file_routes(&main, None)
                    .unwrap()
                    .resolve_crate_root_file(&main, "dev_dep"),
                None,
                // Cargo drops an inferred target that shares an explicit target's
                // path, so the test=false binary is the file's only mode.
                "the explicit test=false binary does not use dev-dependencies"
            );
            assert_eq!(
                rust.file_routes(&example, None)
                    .unwrap()
                    .resolve_crate_root_file(&example, "dev_dep"),
                Some(dependency)
            );
        });
    }

    #[test]
    fn cargo_routes_reject_paths_outside_the_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).expect("workspace root");
        let root = root.canonicalize().expect("canonical root");
        let outside = temp.path().join("outside");
        write(
            temp.path(),
            "outside/Cargo.toml",
            "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
        );
        write(temp.path(), "outside/src/lib.rs", "pub struct Escaped;\n");
        write(
            &root,
            "consumer/Cargo.toml",
            &format!(
                "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nparent_escape = {{ path = \"../../outside\" }}\nabsolute_escape = {{ path = {:?} }}\n",
                outside.to_string_lossy()
            ),
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");

        with_certified_rust_routes(&root, |rust| {
            for name in ["parent_escape", "absolute_escape"] {
                assert_eq!(
                    rust.file_routes(&consumer, None)
                        .unwrap()
                        .resolve_module_package(&consumer, name),
                    None
                );
            }
        });
    }
    #[test]
    #[hardwon(
        "36d2ca4645e4: Two declarations for one physical child merge macro import and retained visibility facts without changing the first source site."
    )]
    fn duplicate_module_edges_merge_into_the_retained_edge() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = 'routes'\nversion = '0.1.0'\nedition = '2021'\n",
        );
        let source = "#[path = \"shared.rs\"]\nmod private;\n#[macro_use]\n#[path = \"shared.rs\"]\nmod imported;\n";
        write(&root, "src/lib.rs", source);
        write(
            &root,
            "src/shared.rs",
            "macro_rules! shared_macro { () => {}; }\n",
        );
        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        with_certified_rust_routes(&root, |rust| {
            let edges = rust
                .file_routes(&library, None)
                .unwrap()
                .module_declarations_declared_in(&library)
                .declarations;

            assert_eq!(edges.len(), 1);
            assert!(edges[0].imports_macros);
            assert_eq!(
                edges[0].declaration_start_byte,
                source.find("mod private").expect("first declaration")
            );
            assert_eq!(
                edges[0].visibility_start_byte,
                source.find("mod imported").expect("macro-use declaration") + "mod imported;".len()
            );
        });
    }
    /// The route index admits a `mod` route written inside item-macro
    /// invocations only when the crate's module walk decides it: every
    /// invocation's macro is a passthrough whose decoration is known. A
    /// passthrough that decorates with `#[allow(..)]` used to be admitted here
    /// while the crate left the route undecided (`UnsupportedMacroGeneratedModule`),
    /// so the two disagreed about which file the crate compiles. A `cfg`
    /// decoration is admitted, and a bare `cfg(test)` decoration gates the
    /// edge as a bare `#[cfg(test)]` on the declaration does.
    #[test]
    #[hardwon(
        "2c4889c1c8da: the route index admitted an allow-decorated macro module that the crate walk left undecided."
    )]
    fn module_child_edges_admit_only_invocations_the_crate_decides() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = 'routes'\nversion = '0.1.0'\nedition = '2021'\n",
        );
        let source = concat!(
            "macro_rules! plain { ($($item:item)*) => { $($item)* }; }\n",
            "macro_rules! unix_only { ($($item:item)*) => { $( #[cfg(unix)] $item )* }; }\n",
            "macro_rules! testing { ($($item:item)*) => { $( #[cfg(test)] $item )* }; }\n",
            "macro_rules! allowed { ($($item:item)*) => { $( #[allow(dead_code)] $item )* }; }\n",
            "plain! { pub mod replayed; }\n",
            "unix_only! { pub mod decorated; }\n",
            "testing! { mod tested; }\n",
            "allowed! { pub mod undecided; }\n",
        );
        write(&root, "src/lib.rs", source);
        for relative in [
            "src/replayed.rs",
            "src/decorated.rs",
            "src/tested.rs",
            "src/undecided.rs",
        ] {
            write(&root, relative, "pub fn item() {}\n");
        }
        let file = ProjectFile::new(root.clone(), "src/lib.rs");
        with_certified_rust_routes(&root, |rust| {
            let edges = rust
                .file_routes(&file, None)
                .unwrap()
                .module_declarations_declared_in(&file)
                .declarations;
            let edge = |name: &str| {
                edges
                    .iter()
                    .find(|edge| edge.target_file.rel_path() == std::path::Path::new(name))
            };
            assert!(
                edge("src/replayed.rs").is_some_and(|edge| !edge.test_gated),
                "{edges:?}"
            );
            assert!(
                edge("src/decorated.rs").is_some_and(|edge| !edge.test_gated),
                "a cfg decoration is admitted for the crate's walk to evaluate: {edges:?}"
            );
            assert!(
                edge("src/tested.rs").is_some_and(|edge| edge.test_gated),
                "a bare cfg(test) decoration gates the edge: {edges:?}"
            );
            assert!(
                edge("src/undecided.rs").is_none(),
                "an undecided invocation admits no route: {edges:?}"
            );
        });
    }

    /// Every module-declaration shape the coordinated producer knows about,
    /// in one file:
    /// plain, directory-backed, `#[path]` on a declaration and on an inline
    /// module, `#[macro_use]`, `#[cfg(test)]`, nested inline scopes, duplicate
    /// declarations of one file, and both a replaying and a non-replaying item
    /// macro.
    const MODULE_ROUTE_FIXTURE: &str = r####"
macro_rules! replay {
    ($($item:item)*) => { $($item)* };
}
macro_rules! swallow {
    ($($item:item)*) => {};
}

mod plain;
mod directory_backed;
#[path = "relocated/target.rs"]
mod relocated_declaration;
#[macro_use]
mod macro_source;
#[cfg(test)]
mod gated;
#[cfg(any(test, feature = "fixtures"))]
mod composed_gate;
pub mod published;

mod outer {
    pub mod inner {
        mod nested_child;
    }
    #[path = "elsewhere"]
    mod relocated_scope {
        mod deep_child;
    }
}

#[path = "shared.rs"]
mod first_alias;
#[macro_use]
#[path = "shared.rs"]
mod second_alias;

replay! { mod replayed; }
swallow! { mod swallowed; }
replay! { replay! { mod doubly_replayed; } }
"####;

    /// Lay the fixture's declared files down on disk. Returns the workspace
    /// root, whose `Cargo.toml` makes it a single-crate workspace.
    fn module_route_fixture(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(
            &root,
            "src/lib.rs",
            &format!("{MODULE_ROUTE_FIXTURE}\nmod sub;\n"),
        );
        for relative in [
            "src/plain.rs",
            "src/directory_backed/mod.rs",
            "src/relocated/target.rs",
            "src/macro_source.rs",
            "src/gated.rs",
            "src/composed_gate.rs",
            "src/published.rs",
            "src/outer/inner/nested_child.rs",
            "src/outer/elsewhere/deep_child.rs",
            "src/elsewhere/deep_child.rs",
            "src/shared.rs",
            "src/replayed.rs",
            "src/swallowed.rs",
            "src/doubly_replayed.rs",
            // A file the crate root does not declare, used to exercise a
            // non-crate-root declaring file.
            "src/sub.rs",
            "src/sub/child.rs",
        ] {
            write(&root, relative, "pub struct Marker;\n");
        }
        write(
            &root,
            "src/sub.rs",
            "mod child;\n#[path = \"../shared.rs\"]\nmod escaped;\n#[path = \"sub/path_child.rs\"]\nmod path_child;\n",
        );
        write(&root, "src/sub/path_child.rs", "pub struct Marker;\n");
        root
    }

    /// Route edges are resolved from the coordinated facts produced by
    /// `parse_rust_file`. Exercise both file-root conventions and the
    /// target-local item-macro visibility that the reader consumes.
    #[test]
    #[hardwon(
        "77b9fe777316: the route index and crate walk disagreed on member admission for nested modules, macro visibility, and cfg."
    )]
    fn module_child_edges_use_coordinated_route_facts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        with_certified_rust_routes(&root, |rust| {
            for relative in ["src/lib.rs", "src/sub.rs"] {
                let file = ProjectFile::new(root.clone(), relative);
                let source = file.read_to_string().expect("read fixture");
                let is_crate_root = relative == "src/lib.rs";
                let visible = true;
                let mut actual = rust
                    .file_routes(&file, None)
                    .unwrap()
                    .module_declarations_declared_in(&file)
                    .declarations;
                let edge = |path: &str,
                            declaring_module: &str,
                            visibility: RustVisibility,
                            imports_macros: bool,
                            test_gated: bool,
                            declaration: &str,
                            visibility_declaration: Option<&str>| {
                    let declaration_start = source.find(declaration).expect("fixture route");
                    RustCargoModuleDeclaration {
                        declaring_file: file.clone(),
                        target_file: ProjectFile::new(root.clone(), path),
                        declaring_module: declaring_module.to_string(),
                        visibility,
                        imports_macros,
                        test_gated,
                        declaration_start_byte: declaration_start,
                        visibility_start_byte: visibility_declaration
                            .map(|declaration| {
                                source.find(declaration).expect("fixture visibility route")
                                    + declaration.len()
                            })
                            .unwrap_or(usize::MAX),
                    }
                };
                let mut expected = match (relative, is_crate_root) {
                    ("src/lib.rs", true) => vec![
                        edge(
                            "src/sub.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod sub;",
                            None,
                        ),
                        edge(
                            "src/composed_gate.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod composed_gate;",
                            None,
                        ),
                        edge(
                            "src/directory_backed/mod.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod directory_backed;",
                            None,
                        ),
                        edge(
                            "src/gated.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            true,
                            "mod gated;",
                            None,
                        ),
                        edge(
                            "src/macro_source.rs",
                            "routes",
                            RustVisibility::Private,
                            true,
                            false,
                            "mod macro_source;",
                            Some("mod macro_source;"),
                        ),
                        edge(
                            "src/outer/elsewhere/deep_child.rs",
                            "routes.outer.relocated_scope",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod deep_child;",
                            None,
                        ),
                        edge(
                            "src/outer/inner/nested_child.rs",
                            "routes.outer.inner",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod nested_child;",
                            None,
                        ),
                        edge(
                            "src/plain.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod plain;",
                            None,
                        ),
                        edge(
                            "src/published.rs",
                            "routes",
                            RustVisibility::Public,
                            false,
                            false,
                            "pub mod published;",
                            None,
                        ),
                        edge(
                            "src/relocated/target.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod relocated_declaration;",
                            None,
                        ),
                        edge(
                            "src/shared.rs",
                            "routes",
                            RustVisibility::Private,
                            true,
                            false,
                            "mod first_alias;",
                            Some("mod second_alias;"),
                        ),
                    ],
                    ("src/lib.rs", false) => vec![
                        edge(
                            "src/relocated/target.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod relocated_declaration;",
                            None,
                        ),
                        edge(
                            "src/shared.rs",
                            "routes",
                            RustVisibility::Private,
                            true,
                            false,
                            "mod first_alias;",
                            Some("mod second_alias;"),
                        ),
                    ],
                    ("src/sub.rs", true) => vec![edge(
                        "src/sub/path_child.rs",
                        "routes.sub",
                        RustVisibility::Private,
                        false,
                        false,
                        "mod path_child;",
                        None,
                    )],
                    ("src/sub.rs", false) => vec![
                        edge(
                            "src/sub/child.rs",
                            "routes.sub",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod child;",
                            None,
                        ),
                        edge(
                            "src/sub/path_child.rs",
                            "routes.sub",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod path_child;",
                            None,
                        ),
                    ],
                    _ => unreachable!("fixture file: {relative}"),
                };
                if relative == "src/lib.rs" && is_crate_root && visible {
                    expected.extend([
                        edge(
                            "src/doubly_replayed.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod doubly_replayed;",
                            None,
                        ),
                        edge(
                            "src/replayed.rs",
                            "routes",
                            RustVisibility::Private,
                            false,
                            false,
                            "mod replayed;",
                            None,
                        ),
                    ]);
                }
                expected.sort_by(|left, right| left.target_file.cmp(&right.target_file));
                actual.sort_by(|left, right| left.target_file.cmp(&right.target_file));
                assert_eq!(
                    actual, expected,
                    "{relative}, root {is_crate_root}, visible {visible}"
                );
            }
        });
    }

    /// The fixture must actually exercise the shapes the pin claims to cover,
    /// or the comparison above would hold vacuously.
    #[test]
    fn the_module_route_fixture_exercises_every_declaration_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        let file = ProjectFile::new(root.clone(), "src/lib.rs");
        let source = file.read_to_string().expect("read fixture");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let facts = brokk_bifrost_rust::declarations::parse_rust_file(&file, &source, &tree)
            .rust_usage_facts
            .module_routes;

        assert!(
            facts
                .scopes
                .iter()
                .any(|scope| scope.path_attribute.is_some()),
            "an inline module carries a #[path]: {facts:?}"
        );
        assert!(
            facts.scopes.iter().any(|scope| scope.parent == Some(0)
                && scope.module_name == "outer"
                && !scope.imports_macros),
            "the inline scopes are recorded with their macro-use chain: {facts:?}"
        );
        assert!(
            facts
                .routes
                .iter()
                .any(|route| route.path_attribute.is_some()),
            "a declaration carries a #[path]: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.test_gated),
            "a bare #[cfg(test)] declaration is gated: {facts:?}"
        );
        assert!(
            facts
                .routes
                .iter()
                .any(|route| route.module_name == "composed_gate" && !route.test_gated),
            "a composed cfg predicate must not gate: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.imports_macros),
            "a #[macro_use] declaration is recorded: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.gates.len() == 1),
            "a single-macro gate is recorded: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.gates.len() == 2),
            "a nested-macro gate chain is recorded: {facts:?}"
        );
        assert!(
            facts.item_macros.len() == 2,
            "both item macros are recorded: {facts:?}"
        );

        // The gates are what the reader filters on, so the two macros must
        // reach opposite verdicts through the real build.
        with_certified_rust_routes(&root, |rust| {
            let edges = rust
                .file_routes(&file, None)
                .unwrap()
                .module_declarations_declared_in(&file)
                .declarations;
            let named = |name: &str| {
                edges
                    .iter()
                    .any(|edge| edge.target_file.rel_path() == Path::new(name))
            };
            assert!(named("src/replayed.rs"), "edges: {edges:?}");
            assert!(named("src/doubly_replayed.rs"), "edges: {edges:?}");
            assert!(!named("src/swallowed.rs"), "edges: {edges:?}");
        });
    }

    #[test]
    fn cargo_boundary_discovered_routes_follow_manifest_dependency_kinds() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../bifrost-rust/tests/fixtures/cargo-matrix")
            .canonicalize()
            .unwrap();
        with_certified_rust_routes(&root, |rust| {
            for (caller, alias, target) in [
                ("app/src/lib.rs", "dep_alias", Some("dep/src/lib.rs")),
                ("app/src/lib.rs", "noise", Some("noise/src/lib.rs")),
                ("app/custom/build.rs", "noise", Some("noise/src/lib.rs")),
                ("app/custom/build.rs", "dep_alias", None),
                ("member/src/lib.rs", "dep_alias", Some("dep/src/lib.rs")),
                (
                    "nested/src/bin/deep/main.rs",
                    "nested",
                    Some("nested/src/lib.rs"),
                ),
            ] {
                assert_eq!(
                    rust.file_routes(&ProjectFile::new(root.clone(), caller), None)
                        .unwrap()
                        .resolve_crate_root_file(&ProjectFile::new(root.clone(), caller), alias),
                    target.map(|p| ProjectFile::new(root.clone(), p)),
                    "{caller}: {alias}"
                );
            }
            for line in
                include_str!("../../../bifrost-rust/tests/fixtures/cargo-matrix/expected.txt")
                    .lines()
            {
                let fields = line.split(" | ").collect::<Vec<_>>();
                let file = ProjectFile::new(root.clone(), fields[1]);
                assert!(
                    rust.file_routes(&file, None)
                        .unwrap()
                        .target_roots(&file)
                        .contains(&file),
                    "explicit or inferred Cargo root: {}",
                    fields[1]
                );
            }
        });
    }

    fn multi_target_workspace(temp: &tempfile::TempDir) -> std::path::PathBuf {
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"engine\", \"app\", \"legacy\"]\nresolver = \"2\"\n",
        );

        write(
            &root,
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n\n[dev-dependencies]\napp = { path = \"../app\" }\n",
        );
        write(&root, "engine/build.rs", "fn main() {}\n");
        write(
            &root,
            "engine/src/lib.rs",
            "#[macro_use]\nmod macros;\npub mod part;\n#[cfg(test)]\nmod tests;\nreplay! { mod expanded; }\nswallow! { mod swallowed; }\n",
        );
        write(
            &root,
            "engine/src/macros.rs",
            "macro_rules! replay {\n    ($($item:item)*) => { $($item)* };\n}\nmacro_rules! swallow {\n    ($($item:item)*) => {};\n}\n",
        );
        write(&root, "engine/src/part.rs", "pub struct Part;\n");
        write(&root, "engine/src/expanded.rs", "pub struct Marker;\n");
        write(&root, "engine/src/swallowed.rs", "pub struct Marker;\n");
        write(&root, "engine/src/tests.rs", "mod helpers;\n");
        write(&root, "engine/src/tests/helpers.rs", "pub fn helper() {}\n");
        // The binary shares the library's module file, so one file belongs to
        // two targets of the same crate.
        write(&root, "engine/src/main.rs", "mod part;\nfn main() {}\n");
        write(
            &root,
            "engine/src/bin/tool.rs",
            "mod support;\nfn main() {}\n",
        );
        write(&root, "engine/src/bin/support.rs", "pub fn support() {}\n");
        // The deepest shape auto discovery accepts, four components below the
        // manifest directory.
        write(
            &root,
            "engine/src/bin/nested/main.rs",
            "mod inner;\nfn main() {}\n",
        );
        write(
            &root,
            "engine/src/bin/nested/inner.rs",
            "pub fn inner() {}\n",
        );
        write(&root, "engine/tests/it.rs", "mod fixtures;\n");
        // `tests/fixtures.rs` is an auto-discovered integration test target in
        // its own right AND a module of `tests/it.rs`, so its own declaration
        // resolves to a different file under each reading. Nothing else in the
        // fixture asks one file for its edges both ways.
        write(
            &root,
            "engine/tests/fixtures.rs",
            "mod shared;\npub fn fixture() {}\n",
        );
        write(&root, "engine/tests/shared.rs", "pub fn shared() {}\n");
        write(
            &root,
            "engine/tests/fixtures/shared.rs",
            "pub fn shared() {}\n",
        );
        write(&root, "engine/benches/bench.rs", "fn main() {}\n");
        write(&root, "engine/examples/demo/main.rs", "fn main() {}\n");

        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nengine = { path = \"../engine\" }\n",
        );
        write(
            &root,
            "app/src/lib.rs",
            "pub mod feature;\n#[path = \"custom/relocated.rs\"]\nmod relocated;\n",
        );
        write(&root, "app/src/feature.rs", "pub struct Marker;\n");
        write(
            &root,
            "app/src/custom/relocated.rs",
            "pub struct Relocated;\n",
        );
        write(&root, "app/src/main.rs", "fn main() {}\n");

        write(
            &root,
            "legacy/Cargo.toml",
            "[package]\nname = \"legacy\"\nversion = \"0.1.0\"\nedition = \"2015\"\n\n[[bin]]\nname = \"legacy-cli\"\npath = \"src/cli.rs\"\n",
        );
        write(&root, "legacy/src/cli.rs", "mod util;\nfn main() {}\n");
        write(&root, "legacy/src/util.rs", "pub fn util() {}\n");
        // The 2015 explicit-target rule is off for binaries here, and on for
        // the library: this file is the package's library target.
        write(&root, "legacy/src/lib.rs", "pub struct Reachable;\n");
        root
    }
    fn analyzed_rust_files(root: &std::path::Path) -> Vec<ProjectFile> {
        let mut files = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("read fixture directory") {
                let path = entry.expect("fixture entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    let relative = path.strip_prefix(root).expect("relative fixture path");
                    files.push(ProjectFile::new(root.to_path_buf(), relative));
                }
            }
        }
        files.sort();
        files
    }
    #[test]
    fn the_multi_target_fixture_exercises_shared_targets_and_expanded_modules() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = multi_target_workspace(&temp);
        with_certified_rust_routes(&root, |rust| {
            let routes = |file: &ProjectFile| rust.file_routes(file, None).unwrap();

            let library = ProjectFile::new(root.clone(), "engine/src/lib.rs");
            let binary = ProjectFile::new(root.clone(), "engine/src/main.rs");
            let part = ProjectFile::new(root.clone(), "engine/src/part.rs");
            let mut part_roots = routes(&part).target_roots(&part);
            part_roots.sort();
            let mut shared = vec![binary, library];
            shared.sort();
            assert_eq!(
                part_roots, shared,
                "one module file must belong to two targets of the same crate"
            );
            let files = analyzed_rust_files(&root);
            let roots = files
                .iter()
                .flat_map(|file| routes(file).target_roots(file))
                .collect::<std::collections::HashSet<_>>();
            assert!(
                roots.len() >= 8,
                "library, three binaries, integration test, bench, example and build script: {roots:?}"
            );
            assert!(
                routes(&ProjectFile::new(
                    root.clone(),
                    "engine/src/bin/nested/inner.rs"
                ))
                .target_roots(&ProjectFile::new(
                    root.clone(),
                    "engine/src/bin/nested/inner.rs"
                ))
                .contains(&ProjectFile::new(
                    root.clone(),
                    "engine/src/bin/nested/main.rs"
                )),
                "the deepest auto-discovered target shape must still own its modules"
            );
            let declared = files
                .iter()
                .flat_map(|file| {
                    routes(file)
                        .module_declarations_declared_in(file)
                        .declarations
                })
                .map(|d| d.target_file.rel_path().to_path_buf())
                .collect::<Vec<_>>();
            assert!(
                declared.contains(&std::path::PathBuf::from("engine/src/expanded.rs")),
                "a passthrough macro's module declaration must survive: {declared:?}"
            );
            assert!(
                !declared.contains(&std::path::PathBuf::from("engine/src/swallowed.rs")),
                "a macro that does not replay its items must not declare a module: {declared:?}"
            );
            assert!(
                declared.contains(&std::path::PathBuf::from("app/src/custom/relocated.rs")),
                "a #[path] declaration must resolve: {declared:?}"
            );
            let test_helper = ProjectFile::new(root.clone(), "engine/src/tests/helpers.rs");
            let helper_routes = routes(&test_helper);
            // Incomplete production routes conservatively never narrow to test-only.
            assert!(!helper_routes.is_complete());
            assert!(!helper_routes.file_is_test_only(&test_helper));
            // Corrected with the pin above: an explicit `[[bin]]` on a 2015 crate
            // disables the implicit binary, example, test and bench targets, and
            // leaves the library alone (Cargo 1.96, `cargo metadata --no-deps`).
            assert_eq!(
                routes(&ProjectFile::new(root.clone(), "legacy/src/lib.rs"))
                    .target_roots(&ProjectFile::new(root.clone(), "legacy/src/lib.rs")),
                [ProjectFile::new(root.clone(), "legacy/src/lib.rs")],
                "an explicit [[bin]] on a 2015 crate leaves the auto library target"
            );
            let it = ProjectFile::new(root.clone(), "engine/tests/it.rs");
            let fixtures = ProjectFile::new(root.clone(), "engine/tests/fixtures.rs");
            assert!(
                routes(&ProjectFile::new(root.clone(), "engine/tests/shared.rs"))
                    .target_roots(&ProjectFile::new(root.clone(), "engine/tests/shared.rs"))
                    .contains(&fixtures),
                "a file that is both a target root and a declared module must resolve \
             its own declarations as a crate root"
            );
            assert!(
                routes(&ProjectFile::new(
                    root.clone(),
                    "engine/tests/fixtures/shared.rs"
                ))
                .target_roots(&ProjectFile::new(
                    root.clone(),
                    "engine/tests/fixtures/shared.rs"
                ))
                .contains(&it),
                "and as a module when it is reached through the file that declares it"
            );
        });
    }
}
