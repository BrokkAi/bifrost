#[cfg(test)]
mod go_overlay_test {

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageGraphBuildOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::build_workspace_usage_graph_with_cancellation;

    use brokk_bifrost_go_analysis::analyzer::go::GoAnalyzer;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::cancellation::CancellationToken;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    #[test]
    fn unreprojected_go_module_overlay_makes_the_workspace_graph_incomplete_and_recovers() {
        use brokk_bifrost_core::analyzer::project::OverlayProject;

        use brokk_bifrost_core::analyzer::project::Project;

        let source = "package app\n\nfunc target() {}\nfunc caller() { target() }\n";
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n")
            .file("app.go", source)
            .build();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        let file = fixture.file("app.go");
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let analyzer = GoAnalyzer::new(overlay.clone() as Arc<dyn Project>);
        let build = |catalog: WorkspaceUsageCatalog| {
            assert!(
                !catalog.nodes.is_empty(),
                "the Go pass must have graph roots"
            );
            build_workspace_usage_graph_with_cancellation(
                &analyzer,
                catalog,
                &BTreeSet::from([UsageEcosystem::Go]),
                &CancellationToken::default(),
            )
        };
        assert!(analyzer.graph_inventory_complete());
        assert!(matches!(
            build(WorkspaceUsageCatalog::build(&analyzer)),
            WorkspaceUsageGraphBuildOutcome::Complete(_)
        ));

        // Preserve the selected roots while invalidating the authority for
        // their package-qualified identities. A source-only edit can be
        // hydrated on demand; a module rename requires workspace reprojection.
        let catalog = WorkspaceUsageCatalog::build(&analyzer);
        let module = fixture.file("go.mod");
        assert!(overlay.set(module.abs_path(), "module example.com/renamed\n".to_owned()));
        assert!(!analyzer.graph_inventory_complete());
        assert!(
            matches!(
                build(catalog),
                WorkspaceUsageGraphBuildOutcome::Incomplete(_)
            ),
            "unreprojected Go identities must not become a complete empty graph"
        );

        assert!(overlay.clear(&module.abs_path()));
        assert!(analyzer.graph_inventory_complete());
        assert!(matches!(
            build(WorkspaceUsageCatalog::build(&analyzer)),
            WorkspaceUsageGraphBuildOutcome::Complete(_)
        ));
    }
}
