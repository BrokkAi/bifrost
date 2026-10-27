#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_13 {
    use brokk_bifrost_analysis::CancellationToken;
    use brokk_bifrost_analysis::analyzer::store::go_package_context::*;
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
    use brokk_bifrost_analysis::analyzer::{
        Language,
        store::{AnalyzerStore, WorkspaceSnapshotId},
    };
    use brokk_bifrost_analysis::inline_project::InlineTestProject;
    use brokk_bifrost_go::package_discovery::GoPackageDiscovery;
    use serde_json::json;
    #[doc(hidden)]
    pub struct Fixture {
        #[doc(hidden)]
        pub project: brokk_bifrost_analysis::inline_project::BuiltInlineTestProject,
        #[doc(hidden)]
        pub workspace: WorkspaceAnalyzer,
        #[doc(hidden)]
        pub snapshot: WorkspaceSnapshotId,
    }
    impl Fixture {
        #[doc(hidden)]
        pub fn new() -> Self {
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/root\n\ngo 1.22\n")
                .file(
                    "consumer/use.go",
                    "package consumer\nimport . \"example.test/root/provider\"\nvar Use *Item\n",
                )
                .file("provider/item.go", "package provider\ntype Item struct{}\n")
                .build();
            Self::from_project(project)
        }
        #[doc(hidden)]
        pub fn from_project(
            project: brokk_bifrost_analysis::inline_project::BuiltInlineTestProject,
        ) -> Self {
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let id = brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(project.root());
            let snapshot = conn.query_row("SELECT generation,revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",[id.as_str()],|row|Ok(WorkspaceSnapshotId {
                workspace_id:id.clone(),lang:"go".into(),generation:brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(row.get(0)?),revision:row.get(1)?,
            })).unwrap();
            drop(conn);
            Self {
                project,
                workspace,
                snapshot,
            }
        }
        #[doc(hidden)]
        pub fn store(&self) -> &AnalyzerStore {
            self.workspace.store().unwrap()
        }
        #[doc(hidden)]
        pub fn observe(&self) -> GoInputObservation {
            let GoInputObservationOutcome::Ready(observation) = self
                .store()
                .observe_go_context_inputs(
                    &self.snapshot,
                    self.workspace.analyzer().project(),
                    &CancellationToken::new(),
                )
                .unwrap()
            else {
                panic!("fixture input is selected");
            };
            observation
        }
        #[doc(hidden)]
        pub fn discovery(&self) -> GoPackageDiscovery {
            let root = self.project.root();
            let module = json!({"Path":"example.test/root","Dir":root,"Main":true,"GoMod":root.join("go.mod")});
            GoPackageDiscovery {
                    domain: brokk_bifrost_go::package_discovery::GoDiscoveryDomain {
                        modules: vec![(String::new(), "example.test/root".into())],
                        ..Default::default()
                    },
                    input_digest: None,
                    failure: None,
                packages: vec![
                    serde_json::from_value(json!({"ImportPath":"example.test/root/consumer","Name":"consumer","Dir":root.join("consumer"),"Module":module,"GoFiles":["use.go"],"Imports":["example.test/root/provider"]})).unwrap(),
                    serde_json::from_value(json!({"ImportPath":"example.test/root/provider","Name":"provider","Dir":root.join("provider"),"Module":module,"GoFiles":["item.go"]})).unwrap(),
                ],
                environment:serde_json::from_value(json!({"GOROOT":root.join("sdk"),"GOPATH":root.join("gopath"),"GOMODCACHE":root.join("modules"),"GOVERSION":"go1.22.0","GOWORK":"off","GOOS":"linux","GOARCH":"amd64"})).unwrap(),
                build_configuration:brokk_bifrost_go::package_discovery::GoBuildConfiguration{
                    goos:"linux".into(),goarch:"amd64".into(),cgo_enabled:false,tags:Vec::new(),
                },workspace_patterns:vec!["./consumer".into()],vendor:false,
            }
        }
        #[doc(hidden)]
        pub fn publish(
            &self,
            discovery: GoPackageDiscovery,
            expected: Option<GoContextIdentity>,
        ) -> GoContextIdentity {
            let before = self.observe();
            let after = self.observe();
            let GoContextPublicationOutcome::Published(identity) = self
                .store()
                .publish_go_package_context(
                    self.snapshot.clone(),
                    self.project.root().to_path_buf(),
                    expected,
                    &before,
                    &after,
                    discovery,
                    &CancellationToken::new(),
                )
                .unwrap()
            else {
                panic!("fixture publication must succeed");
            };
            identity
        }
    }
}

pub mod collection_fixtures {
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, Language, Project, TestProject,
        store::{AnalyzerStore, WorkspaceId},
        workspace::WorkspaceAnalyzer,
    };
    use brokk_bifrost_core::gitblob::test_repo::{commit_all, init_repo};
    use std::path::PathBuf;
    use std::sync::Arc;
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub struct TwoRevisionCollectionFixture {
        #[doc(hidden)]
        pub root: PathBuf,
        #[doc(hidden)]
        pub repository: git2::Repository,
        #[doc(hidden)]
        pub db_path: PathBuf,
        #[doc(hidden)]
        pub store: AnalyzerStore,
        _temp: tempfile::TempDir,
    }
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn two_revision_collection_fixture() -> TwoRevisionCollectionFixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = "pub fn widget() -> u32 { 1 }\n";
        let second = "pub fn widget() -> u32 { 2 }\npub fn extra() -> u32 { 3 }\n";
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();
        let repository = init_repo(&root);
        let first_commit = commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            Arc::clone(&project),
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        std::fs::write(root.join("app.rs"), second).unwrap();
        commit_all(&repository, "second content");
        drop(
            WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                Arc::clone(&project),
                AnalyzerConfig::default(),
            )
            .expect("persisted analyzer should rebuild"),
        );

        let head = repository.head().unwrap();
        let branch = head.name().expect("a named branch").to_string();
        repository
            .reference(&branch, first_commit, true, "drop the second commit")
            .unwrap();
        drop(head);
        std::fs::write(root.join("app.rs"), first).unwrap();

        let store = AnalyzerStore::open_persistent(&db_path).expect("open the collected store");
        assert!(
            store
                .delete_workspace_projection(&WorkspaceId::for_root(&root))
                .expect("release the workspace projection")
                > 0
        );

        TwoRevisionCollectionFixture {
            _temp: temp,
            root,
            repository,
            db_path,
            store,
        }
    }
}
