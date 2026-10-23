#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use std::sync::Arc;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::WorkspaceBuildSnapshot;

    use brokk_bifrost_analysis::analyzer::store::liveness::Liveness;

    use brokk_bifrost_core::analyzer::project::FilesystemProject;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::gitblob::test_repo::commit_all;

    use brokk_bifrost_core::gitblob::test_repo::init_repo;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::atomic::Ordering;
    #[cfg(test)]
    #[test]
    #[hardwon(
        "#2542: overlay source identity was recomputed during workspace snapshot construction"
    )]
    fn build_snapshot_hashes_overlay_source_once_as_an_overlay_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(&root, "Sample.java");
        std::fs::write(file.abs_path(), "class Disk {}\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "overlay source");

        let base: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = Arc::new(OverlayProject::new(base));
        let overlay_source = "class Overlay {}\n";
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let repository = brokk_bifrost_core::gitblob::discover(&root).unwrap();
        let liveness = Liveness::new(repository).unwrap();
        let snapshot =
            WorkspaceBuildSnapshot::capture(overlay.as_ref(), Some(&liveness), &[Language::Java])
                .expect("Git-backed overlay snapshot");
        let entry = snapshot
            .live_entry(overlay.as_ref(), &file)
            .expect("overlay live entry");
        assert_eq!(
            liveness.startup_oid_batch_counter().load(Ordering::Relaxed),
            0
        );
        let expected =
            git2::Oid::hash_object(git2::ObjectType::Blob, overlay_source.as_bytes()).unwrap();
        assert_eq!(entry.oid(), expected);
        assert!(entry.is_overlay());

        let updated_overlay_source = "class OverlayTwo {}\n";
        assert!(overlay.set(file.abs_path(), updated_overlay_source.to_owned()));
        assert!(snapshot.live_entry(overlay.as_ref(), &file).is_none());
        let refreshed =
            WorkspaceBuildSnapshot::capture(overlay.as_ref(), Some(&liveness), &[Language::Java])
                .expect("refreshed overlay snapshot");
        let refreshed_entry = refreshed
            .live_entry(overlay.as_ref(), &file)
            .expect("refreshed overlay live entry");
        let refreshed_expected =
            git2::Oid::hash_object(git2::ObjectType::Blob, updated_overlay_source.as_bytes())
                .unwrap();
        assert_eq!(refreshed_entry.oid(), refreshed_expected);

        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&overlay) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral overlay workspace");
        assert!(
            workspace
                .analyzer()
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "OverlayTwo")
        );
    }
}
