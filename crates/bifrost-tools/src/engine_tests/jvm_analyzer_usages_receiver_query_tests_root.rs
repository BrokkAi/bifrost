#[cfg(test)]
mod jvm_extraction_tests {

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::assert_factory_ranges_limited_and_cancellable;

    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use std::path::PathBuf;
    #[test]
    fn java_factory_ranges_are_limited_and_cancellable_without_file_hydration() {
        let source = r#"
class Service {}
class Sample {
static Service makeService() { return new Service(); }
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Sample.java"));
        file.write(source).expect("write source");
        let project = Arc::new(TestProject::new(root, Language::Java));
        {
            let _cold =
                WorkspaceAnalyzer::build_persisted(project.clone(), AnalyzerConfig::default())
                    .expect("cold persisted Java workspace");
        }
        let workspace = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("warm persisted Java workspace");
        let factory = workspace
            .analyzer()
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name().ends_with("Sample.makeService"))
            .expect("persisted Java factory");
        let java = resolve_analyzer::<JavaAnalyzer>(workspace.analyzer())
            .expect("workspace Java analyzer");
        java.inner().reset_full_hydration_count_for_test();

        assert_factory_ranges_limited_and_cancellable(workspace.analyzer(), &factory);
        assert_eq!(
            java.inner().full_hydration_count_for_test(),
            0,
            "bounded Java factory-range validation must not hydrate persisted FileState"
        );
    }
}
