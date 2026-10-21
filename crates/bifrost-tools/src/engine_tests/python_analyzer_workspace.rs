#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::CodeUnitIndex;
    use brokk_bifrost_analysis::analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackActivationOutcome;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext;

    use brokk_bifrost_analysis::analyzer::workspace::EmptyAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use crate::analyzer::semantic_model::Completeness;

    use crate::analyzer::semantic_model::DependencyPackDiagnosticSeverity;

    use crate::analyzer::semantic_model::SemanticModelRuntimeLimits;

    use brokk_bifrost_core::analyzer::project::FilesystemProject;

    use brokk_bifrost_core::analyzer::project::MultiRootProject;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::config::PythonEnvironmentConfig;

    use brokk_bifrost_core::analyzer::config::PythonEnvironmentLimits;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::gitblob::test_repo::commit_all;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::gitblob::test_repo::init_repo;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::Connection;
    use std::path::PathBuf;
    #[test]
    fn scoped_cache_projections_are_isolated_and_retained_by_analyzer_clones() {
        let fixture = InlineTestProject::new()
            .file("src/app.py", "class Box:\n    pass\n")
            .file("other/extra.py", "class Extra:\n    pass\n")
            .with_git()
            .build();
        let first_project: Arc<dyn Project> =
            Arc::new(brokk_bifrost_core::analyzer::project::FileSetProject::new(
                fixture.root(),
                [PathBuf::from("src/app.py")],
            ));
        let second_project: Arc<dyn Project> =
            Arc::new(brokk_bifrost_core::analyzer::project::FileSetProject::new(
                fixture.root(),
                [PathBuf::from("other/extra.py")],
            ));
        assert!(first_project.persistence_root().is_none());
        let first = WorkspaceAnalyzer::build_scoped_persisted(
            Arc::clone(&first_project),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let second =
            WorkspaceAnalyzer::build_scoped_persisted(second_project, AnalyzerConfig::default())
                .unwrap();
        let conn = Connection::open(brokk_bifrost_analysis::analyzer::store::analyzer_db_path(
            fixture.root(),
        ))
        .unwrap();
        let projection_files = || {
            conn.prepare(
                "SELECT workspace_id, rel_path FROM workspace_file_versions
                 WHERE valid_until IS NULL ORDER BY rel_path",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };
        let files = projection_files();
        assert_eq!(files.len(), 2, "overlapping scope lifetimes: {files:?}");
        assert_eq!(files[0].1, "other/extra.py");
        assert_eq!(files[1].1, "src/app.py");
        assert_ne!(files[0].0, files[1].0);
        let live_id = brokk_bifrost_core::gitblob::workspace_cache_identity(fixture.root());
        assert!(files.iter().all(|(id, _)| id != &live_id));

        let retained = first.clone_with_project(Arc::clone(&first_project));
        drop(first);
        assert_eq!(
            projection_files(),
            files,
            "clones must retain the projection"
        );
        drop(second);
        assert_eq!(projection_files(), vec![files[1].clone()]);
        let declarations = retained.analyzer().get_all_declarations();
        let classes: Vec<_> = declarations
            .iter()
            .filter(|unit| unit.is_class())
            .map(|unit| unit.identifier())
            .collect();
        assert_eq!(classes, vec!["Box"], "retained scope: {declarations:?}");
        assert!(
            declarations
                .iter()
                .all(|unit| unit.source() == &fixture.file("src/app.py"))
        );
        drop(retained);
        assert!(projection_files().is_empty());
        for table in ["workspace_heads", "workspace_revisions"] {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "session must release {table}");
        }
        let blobs: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(blobs, 2, "projection cleanup must retain content facts");
        let warm =
            WorkspaceAnalyzer::build_scoped_persisted(first_project, AnalyzerConfig::default())
                .unwrap();
        let provider = warm.analyzer().structural_fact_providers()[0];
        assert_eq!(provider.structural_extraction_count(), 0);
        assert_eq!(
            std::collections::HashSet::<_>::from_iter(warm.analyzer().get_all_declarations()),
            std::collections::HashSet::<_>::from_iter(declarations),
        );
    }
    #[test]
    #[hardwon(
        "#2542: Kotlin cold query startup repeated workspace listings and blob identity hashing"
    )]
    fn git_multilanguage_build_reuses_constructor_listing_and_one_oid_batch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Sample.java"), "class Sample {}\n").unwrap();
        std::fs::write(root.join("sample.py"), "class SamplePy:\n    pass\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "multi-language workspace");

        let project = Arc::new(FilesystemProject::new(&root).unwrap());
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral multi-language workspace");

        assert_eq!(
            project.workspace_file_listing_count(),
            1,
            "the constructor listing should seed the one build snapshot"
        );
        assert_eq!(workspace.startup_oid_batch_count_for_test(), 1);
        assert!(
            workspace
                .analyzer()
                .declarations(&ProjectFile::new(&root, "Sample.java"))
                .iter()
                .any(|unit| unit.identifier() == "Sample")
        );
        assert!(
            workspace
                .analyzer()
                .declarations(&ProjectFile::new(&root, "sample.py"))
                .iter()
                .any(|unit| unit.identifier() == "SamplePy")
        );

        let late = ProjectFile::new(&root, "late.go");
        std::fs::write(late.abs_path(), "package late\n").unwrap();
        assert!(project.all_files_shared().unwrap().contains(&late));
        assert_eq!(
            project.workspace_file_listing_count(),
            2,
            "manual sessions must return to a fresh walk after the build seed"
        );
    }
    #[test]
    #[hardwon("#2542: non-Git cold startup repeated constructor path listings")]
    fn non_git_multilanguage_build_reuses_one_listing_without_live_oids() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Sample.java"), "class Sample {}\n").unwrap();
        std::fs::write(root.join("sample.py"), "class SamplePy:\n    pass\n").unwrap();
        let project = Arc::new(TestProject::from_root_with_inferred_languages(&root).unwrap());
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral non-Git workspace");

        assert_eq!(project.workspace_file_listing_count(), 1);
        assert_eq!(workspace.startup_oid_batch_count_for_test(), 0);
        assert!(workspace.analyzer().languages().contains(&Language::Java));
        assert!(workspace.analyzer().languages().contains(&Language::Python));
    }
    #[test]
    #[hardwon(
        "#2542: multi-root startup repeated the source listing for each constructor consumer"
    )]
    fn multi_root_build_consumes_each_constructor_seed_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let java_root = root.join("java");
        let python_root = root.join("python");
        std::fs::create_dir_all(&java_root).unwrap();
        std::fs::create_dir_all(&python_root).unwrap();
        std::fs::write(java_root.join("Sample.java"), "class Sample {}\n").unwrap();
        std::fs::write(python_root.join("sample.py"), "class SamplePy:\n    pass\n").unwrap();

        let project = Arc::new(MultiRootProject::new([java_root, python_root]).unwrap());
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral multi-root workspace");

        assert_eq!(project.workspace_file_listing_count(), 2);
        assert!(workspace.analyzer().languages().contains(&Language::Java));
        assert!(workspace.analyzer().languages().contains(&Language::Python));

        let late = root.join("java").join("late.go");
        std::fs::write(&late, "package late\n").unwrap();
        let late_file = ProjectFile::new(&root, "java/late.go");
        assert!(project.all_files_shared().unwrap().contains(&late_file));
        assert_eq!(project.workspace_file_listing_count(), 4);
    }
    #[test]
    #[hardwon("#847: unsupported analyzer queries must remain healthy empty results")]
    fn unsupported_analyzer_query_remains_a_healthy_empty_result() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let analyzer = EmptyAnalyzer::new(project);
        let context =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());

        analyzer.begin_query(&context);
        assert!(analyzer.definitions("Missing").next().is_none());
        assert!(context.store_error().is_none());
        analyzer.end_query(&context);
    }
    /// Activate the Python ecosystem against a fabricated environment whose
    /// standard-library root contains exactly `files`, with no intrinsic
    /// activation evidence, so the outcome is decided by dependency
    /// preparation alone.
    fn activate_python_stdlib_environment(
        files: &[(&str, &[u8])],
    ) -> DependencyPackActivationOutcome {
        let project = InlineTestProject::with_language(Language::Python)
            .file("main.py", "value = 1\n")
            .build();
        let stdlib_root = project.root().join(".env/stdlib");
        std::fs::create_dir_all(&stdlib_root).expect("create stdlib root");
        for (name, contents) in files {
            std::fs::write(stdlib_root.join(name), contents)
                .unwrap_or_else(|error| panic!("write stdlib artifact {name}: {error}"));
        }
        let mut config = AnalyzerConfig::default();
        config.python.environment = Some(PythonEnvironmentConfig {
            implementation: "cpython".to_owned(),
            version: "3.12.0".to_owned(),
            platform: "linux".to_owned(),
            standard_library_root: PathBuf::from(".env/stdlib"),
            bundled_stub_roots: Vec::new(),
            distribution_roots: Vec::new(),
            limits: PythonEnvironmentLimits::default(),
        });
        let workspace = project.workspace_analyzer(config.clone());
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        workspace.activate_dependency_packs(
            &config,
            &[DependencyPackEcosystem::Python],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &request,
                limits: DependencyPackLimits::default(),
                cancellation: &brokk_bifrost_core::cancellation::CancellationToken::default(),
            },
        )
    }
    #[test]
    #[hardwon(
        "b610cdc85704: zero-config Servlet-to-JDBC proof dropped supported evidence from partial generated packs"
    )]
    fn partial_generated_pack_activates_while_preparation_stays_incomplete() {
        let outcome = activate_python_stdlib_environment(&[
            (
                "good.py",
                b"class Greeter:\n    def hello(self) -> int:\n        return 1\n".as_slice(),
            ),
            // Not valid UTF-8, so the producer fails this one artifact while
            // the class above still yields a usable partial declaration pack.
            ("broken.py", &[0xff, 0xfe, 0x00]),
        ]);
        let preparation = outcome.ecosystems[0]
            .preparation
            .as_ref()
            .expect("python environment preparation must run");
        assert!(!preparation.complete, "{preparation:#?}");
        assert!(
            preparation.diagnostics.iter().any(|diagnostic| {
                diagnostic.severity == DependencyPackDiagnosticSeverity::Error
                    && diagnostic.code == "python.source.encoding"
            }),
            "{preparation:#?}"
        );
        assert!(
            !preparation.evidence.is_empty(),
            "the produced partial pack must carry typed activation evidence: {preparation:#?}"
        );
        assert!(!outcome.complete(), "{outcome:#?}");
        assert!(outcome.diagnostic_refresh_required, "{outcome:#?}");
        let SemanticModelRuntimeOutcome::Ready { active, .. } = outcome
            .runtime
            .expect("partial pack evidence must still activate the runtime")
        else {
            panic!("partial pack activation should be ready")
        };
        assert_eq!(active.shards().len(), 1, "{active:#?}");
        assert_eq!(
            active.shards()[0].manifest.pack_id,
            "bifrost.external.python"
        );
        assert_eq!(
            active.shards()[0].manifest.completeness,
            Completeness::Partial
        );
    }
    #[test]
    #[hardwon(
        "b610cdc85704: failed preparation without proof evidence published an inferred model"
    )]
    fn failed_preparation_without_evidence_publishes_nothing() {
        let outcome = activate_python_stdlib_environment(&[("broken.py", &[0xff, 0xfe, 0x00])]);
        let preparation = outcome.ecosystems[0]
            .preparation
            .as_ref()
            .expect("python environment preparation must run");
        assert!(!preparation.complete, "{preparation:#?}");
        assert!(
            preparation.evidence.is_empty(),
            "a failed production must not leave activation evidence: {preparation:#?}"
        );
        assert!(
            outcome.ecosystems[0].discovery.complete,
            "discovery, not preparation, must own this outcome's incompleteness shape"
        );
        assert!(outcome.runtime.is_none(), "{outcome:#?}");
        assert!(!outcome.diagnostic_refresh_required, "{outcome:#?}");
        assert!(!outcome.complete(), "{outcome:#?}");
    }
}
