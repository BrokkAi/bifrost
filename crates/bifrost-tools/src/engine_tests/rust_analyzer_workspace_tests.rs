#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use std::sync::Arc;

    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;
    /// Rust readiness requires verified publication, not just the absence of a
    /// scheduled repair. Warmth additionally requires the catch-up to settle.
    /// The two Rust usage predicates a caller can ask a workspace, and the
    /// distinction ExecPlan Milestone 3 introduced between them: readiness is
    /// "would a query wait", which a healthy workspace answers `true` even
    /// before any warm because v2 has nothing to build, and warmth is "has the
    /// catch-up run for this generation", which only the warm makes true.
    /// Neither may be `false` for a workspace with no Rust.
    #[test]
    fn rust_usage_readiness_and_warmth_are_distinct_and_vacuous_without_rust() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write("pub mod worker;\npub fn root() {}\n")
            .unwrap();
        ProjectFile::new(root.clone(), "src/worker.rs")
            .write("use crate::root;\npub fn run() { root(); }\n")
            .unwrap();

        let rust: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let rust = WorkspaceAnalyzer::build_ephemeral_footgun(rust, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(!rust.rust_usage_facts_ready());
        assert!(!rust.rust_usage_facts_warm());
        rust.warm_rust_usage_facts();
        assert!(rust.rust_usage_facts_ready());
        assert!(rust.rust_usage_facts_warm());

        let java: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let java = WorkspaceAnalyzer::build_ephemeral_footgun(java, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(java.rust_usage_facts_ready());
        assert!(java.rust_usage_facts_warm());
    }

    #[test]
    fn warm_query_indexes_reaches_language_analyzers_through_every_workspace_shape() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write("trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n")
            .unwrap();

        let single: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let single = WorkspaceAnalyzer::build_ephemeral_footgun(single, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(!single.query_indexes_warm());
        single.warm_query_indexes();
        assert!(single.query_indexes_warm());

        let multi: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root,
            BTreeSet::from([Language::Rust, Language::Java]),
        ));
        let multi = WorkspaceAnalyzer::build_ephemeral_footgun(multi, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(!multi.query_indexes_warm());
        multi.warm_query_indexes();
        assert!(multi.query_indexes_warm());
    }
}
