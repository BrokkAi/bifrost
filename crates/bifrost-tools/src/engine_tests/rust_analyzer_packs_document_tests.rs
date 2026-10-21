#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

    use brokk_bifrost_analysis::analyzer::packs_document::WorkspaceActivationSources;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_analysis::analyzer::packs_document::activate_workspace_semantic_sources;

    use brokk_bifrost_analysis::analyzer::packs_document::parse_workspace_packs_config;
    use brokk_bifrost_test_macros::hardwon;
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;
    fn assert_ambient_cargo_activation(
        workspace: &WorkspaceAnalyzer,
        workspace_root: &std::path::Path,
    ) {
        let activation = activate_workspace_semantic_sources(
            workspace,
            &AnalyzerConfig::default(),
            WorkspaceActivationSources {
                catalog_root: workspace_root,
                workspace_model_root: None,
                config: None,
                intrinsic_shipped_models: false,
            },
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .unwrap()
        .expect("the ambient Cargo ecosystem should be selected");
        assert_eq!(activation.ecosystems, [DependencyPackEcosystem::Cargo]);
    }

    #[test]
    fn an_absent_document_activates_every_ecosystem_for_present_languages() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("lib.rs"), "pub fn value() {}\n").unwrap();
        let project = Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::new(temp.path()).unwrap(),
        );
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        assert_ambient_cargo_activation(&workspace, temp.path());
        assert!(
            !temp
                .path()
                .join(brokk_bifrost_core::gitblob::PROJECT_DIR_NAME)
                .exists(),
            "ephemeral ambient activation must not create workspace-generated state"
        );
    }

    #[test]
    #[hardwon(
        "aeabae70329c: persisted activation must retain its versioned generated-pack catalog"
    )]
    fn persisted_ambient_activation_keeps_the_versioned_catalog() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("lib.rs"), "pub fn value() {}\n").unwrap();
        let project = Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::new(temp.path()).unwrap(),
        );
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            project,
            AnalyzerConfig::default(),
        )
        .unwrap();

        assert_ambient_cargo_activation(&workspace, temp.path());
        assert!(
            crate::analyzer::semantic_model::default_semantic_pack_catalog_root(temp.path())
                .exists(),
            "persisted activation must retain the reusable versioned catalog"
        );
    }

    #[test]
    fn an_empty_document_disables_ambient_dependency_activation() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("lib.rs"), "pub fn value() {}\n").unwrap();
        let project = Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::new(temp.path()).unwrap(),
        );
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        let config = parse_workspace_packs_config(
            r#"{ "schema_version": 1, "catalog": ".bifrost/disabled-catalog", "ecosystems": [] }"#,
        )
        .unwrap();
        assert!(
            activate_workspace_semantic_sources(
                &workspace,
                &AnalyzerConfig::default(),
                WorkspaceActivationSources {
                    catalog_root: temp.path(),
                    workspace_model_root: None,
                    config: Some(&config),
                    intrinsic_shipped_models: false,
                },
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            !temp.path().join(".bifrost/disabled-catalog").exists(),
            "disabled activation must not create or mutate a configured catalog"
        );
    }
}
