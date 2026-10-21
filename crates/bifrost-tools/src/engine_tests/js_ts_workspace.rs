#[cfg(test)]
mod js_ts_extraction_tests {

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use std::sync::Arc;

    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::gitblob::test_repo::commit_all;

    use brokk_bifrost_core::gitblob::test_repo::init_repo;

    use rusqlite::Connection;

    #[test]
    fn semantic_generation_check_rejects_a_stale_configuration_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "src/generation.ts");
        file.write("export const generation = 1;\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::TypeScript));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut budget = brokk_bifrost_analysis::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest::new(
                    &mut budget,
                    &cancellation,
                ),
            )
            .unwrap()
            .available_value()
            .cloned()
            .expect("semantic artifact");
        assert!(
            workspace
                .semantic_artifact_key_is_current(artifact.key(), usize::MAX)
                .unwrap()
                .expect("source within limit")
        );

        let current = artifact.key();
        let stale = brokk_bifrost_analysis::analyzer::semantic::SemanticArtifactKey::new(
            current.mount(),
            current.path().clone(),
            current.language(),
            current.revision(),
            current.adapter().clone(),
            current.ir_version(),
            brokk_bifrost_analysis::analyzer::semantic::ConfigurationFingerprint::hash_bytes(
                b"stale-configuration",
            ),
            current.dependencies(),
        );
        assert_eq!(
            workspace
                .semantic_artifact_key_is_current(&stale, usize::MAX)
                .unwrap(),
            Some(false)
        );
    }
    #[test]
    fn request_overlay_snapshot_cannot_replace_committed_structural_facts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let disk_source = "export const disk = call(1);\n";
        let overlay_source = "export const overlay = call(1, 2);\nexport const extra = call(3);\n";
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.ts"), disk_source).unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "disk source");
        let project: Arc<dyn Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root.clone(), "app.ts");

        let disk_workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should build");
        let disk_provider = disk_workspace.analyzer().structural_fact_providers()[0];
        let disk_facts = disk_provider.structural_facts(&file).unwrap();
        let disk_fact_count = disk_facts.nodes().len();
        assert_eq!(disk_facts.source(), disk_source);

        let overlay = Arc::new(OverlayProject::new(Arc::clone(&project)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let overlay_workspace =
            disk_workspace.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        let overlay_provider = overlay_workspace.analyzer().structural_fact_providers()[0];
        let extractions_before = overlay_provider.structural_extraction_count();
        let overlay_facts = overlay_provider.structural_facts(&file).unwrap();
        assert_eq!(overlay_facts.source(), overlay_source);
        assert_ne!(overlay_facts.nodes().len(), disk_fact_count);
        assert_eq!(
            overlay_provider.structural_extraction_count(),
            extractions_before + 1,
            "the unseen overlay blob must extract its own facts"
        );
        drop(overlay_workspace);
        drop(disk_workspace);

        let disk_reopened = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("persisted analyzer should reopen");
        let disk_provider = disk_reopened.analyzer().structural_fact_providers()[0];
        let hydrated_before = disk_provider.structural_hydration_count();
        let disk_facts = disk_provider.structural_facts(&file).unwrap();
        assert_eq!(disk_facts.source(), disk_source);
        assert_eq!(disk_facts.nodes().len(), disk_fact_count);
        assert_eq!(disk_provider.structural_extraction_count(), 0);
        assert_eq!(
            disk_provider.structural_hydration_count(),
            hydrated_before + 1
        );
        drop(disk_reopened);

        let disk_oid = git2::Oid::hash_object(git2::ObjectType::Blob, disk_source.as_bytes())
            .expect("hash committed source");
        let committed_fact_manifests = Connection::open(
            brokk_bifrost_analysis::analyzer::store::analyzer_db_path(&root),
        )
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM structural_source_manifests
                 WHERE blob_id = (
                   SELECT id FROM blobs
                   WHERE blob_oid = ?1 AND lang = 'typescript:ts'
                 )",
            [disk_oid.to_string()],
            |row| row.get::<_, usize>(0),
        )
        .unwrap();
        assert_eq!(
            committed_fact_manifests, 1,
            "overlay analysis must not replace the committed source facts"
        );
    }
    #[test]
    fn multi_workspace_derived_cache_uses_configured_budget_share() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root,
            BTreeSet::from([Language::Java, Language::TypeScript]),
        ));
        let config = AnalyzerConfig {
            memo_cache_budget_bytes: Some(1024 * 1024),
            ..AnalyzerConfig::default()
        };
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), config)
            .expect("ephemeral workspace should build");
        assert_eq!(
            workspace
                .analyzer()
                .snapshot_caches()
                .expect("multi workspace caches")
                .derived_layers()
                .max_retained_bytes(),
            128 * 1024
        );

        let overlay = Arc::new(OverlayProject::new(project));
        let snapshot = workspace.clone_with_project(overlay as Arc<dyn Project>);
        assert_eq!(
            snapshot
                .analyzer()
                .snapshot_caches()
                .expect("snapshot caches")
                .derived_layers()
                .max_retained_bytes(),
            128 * 1024
        );
    }
}
