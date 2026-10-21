#[cfg(test)]
mod ruby_extraction_tests {

    use std::collections::BTreeSet;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageGraphBuildOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::build_workspace_usage_graph_with_cancellation;

    use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    /// Losing the canonical Rust facts must not become a complete empty graph.
    ///
    /// A blob whose fact manifests are gone also fails `source_fact_readiness`,
    /// which is part of the analyzed-file predicate, so it is not in
    /// `analyzed_files` at all. This consumer's preflight therefore asks about
    /// the analyzable inventory, which still holds the file, and the pass is
    /// skipped with the build reported incomplete. Taking the preflight's set
    /// from the analyzed listing would have hidden the one file the preflight
    /// exists to report and let the projection fail one stage later instead.
    #[test]
    fn unavailable_rust_facts_make_the_workspace_graph_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        ProjectFile::new(root.clone(), "Cargo.toml")
            .write(
                "[package]\nname = \"workspace_graph\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .unwrap();
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write("pub fn target() {}\n")
            .unwrap();

        let project = TestProject::new(root, Language::Rust);
        let analyzer = RustAnalyzer::from_project(project);
        let catalog = WorkspaceUsageCatalog::build(&analyzer);
        analyzer.analyzer_store().delete_rust_facts_for_test("rust");

        let outcome = build_workspace_usage_graph_with_cancellation(
            &analyzer,
            catalog,
            &BTreeSet::from([UsageEcosystem::Rust]),
            &CancellationToken::default(),
        );
        let described = match &outcome {
            WorkspaceUsageGraphBuildOutcome::Complete(graph) => {
                format!("Complete({} edges)", graph.edges.len())
            }
            WorkspaceUsageGraphBuildOutcome::Incomplete(graph) => {
                format!("Incomplete({} edges)", graph.edges.len())
            }
            WorkspaceUsageGraphBuildOutcome::Cancelled => "Cancelled".to_owned(),
            WorkspaceUsageGraphBuildOutcome::Stale => "Stale".to_owned(),
            WorkspaceUsageGraphBuildOutcome::Unavailable(reason) => {
                format!("Unavailable({reason})")
            }
            WorkspaceUsageGraphBuildOutcome::Failed(error) => format!("Failed({error})"),
        };
        assert!(
            matches!(outcome, WorkspaceUsageGraphBuildOutcome::Incomplete(_)),
            "missing canonical Rust facts must not become a complete empty graph: {described}"
        );
    }
}
