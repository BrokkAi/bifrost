#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::DerivedLayerBuildMetrics;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::DerivedLayerBuildOutcome;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::DirectImportTopologyLimits;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::build_direct_import_topology;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_jvm_analysis::analyzer::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use std::path::PathBuf;

    #[test]
    fn topology_construction_preflights_fixed_memory_before_resolution() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "bench/Target.java")
            .write("package bench; public class Target {}\n")
            .expect("write target");
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let build = build_direct_import_topology(
            &analyzer,
            token,
            &CancellationToken::default(),
            DirectImportTopologyLimits {
                max_files: 100,
                max_edges: 100,
                max_retained_bytes: 1,
            },
        );

        assert!(matches!(
            build.outcome,
            DerivedLayerBuildOutcome::Unavailable {
                over_budget: true,
                metrics: DerivedLayerBuildMetrics {
                    resolved_files: 0,
                    resolved_edges: 0,
                    ..
                },
                ..
            }
        ));
        assert!(build.fallback.is_none());
    }
    #[test]
    fn topology_limits_reject_without_returning_partial_edges() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), PathBuf::from("bench/Target.java"))
            .write("package bench; public class Target {}\n")
            .expect("write target");
        ProjectFile::new(root.clone(), PathBuf::from("bench/Consumer.java"))
            .write("package bench; import bench.Target; public class Consumer {}\n")
            .expect("write consumer");
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let outcome = build_direct_import_topology(
            &analyzer,
            token,
            &CancellationToken::default(),
            DirectImportTopologyLimits {
                max_files: 100,
                max_edges: 0,
                max_retained_bytes: 1024 * 1024,
            },
        );

        assert!(matches!(
            outcome.outcome,
            DerivedLayerBuildOutcome::Unavailable {
                over_budget: true,
                ..
            }
        ));
        assert!(outcome.fallback.is_some());
    }
}
