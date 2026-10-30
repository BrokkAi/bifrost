#[cfg(test)]
mod ruby_extraction_tests {
    use brokk_bifrost_analysis::{CodeUnitIndex, IAnalyzer};

    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::test_support::acquire_usage_graph;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::test_support::ecosystem_identity;

    use crate::engine_tests::rust_multi_analyzer_support::two_language_analyzer;
    /// Milestone J (#2449) case (a): a usage graph is scoped to its ecosystems,
    /// so an edit to a language outside them must leave it reusable. Before the
    /// caches were content-keyed, the whole cache was minted fresh on every
    /// update and this graph was rebuilt for a file it does not contain.
    #[test]
    fn an_edit_to_one_language_keeps_another_ecosystems_usage_graph() {
        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheLifecycle;

        let (_temp, analyzer) = two_language_analyzer();
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&analyzer, UsageEcosystem::Rust)
        );
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&analyzer, UsageEcosystem::Jvm)
        );

        let java = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        std::fs::write(
            java.abs_path(),
            "package app;\npublic class App { void added() {} }\n",
        )
        .unwrap();
        let updated = analyzer.update(&BTreeSet::from([java]));

        assert_eq!(
            ecosystem_identity(&analyzer, UsageEcosystem::Rust),
            ecosystem_identity(&updated, UsageEcosystem::Rust),
            "a Java edit must not move the Rust content identity"
        );
        assert_ne!(
            ecosystem_identity(&analyzer, UsageEcosystem::Jvm),
            ecosystem_identity(&updated, UsageEcosystem::Jvm),
            "a Java edit must move the JVM content identity"
        );
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Hit,
            acquire_usage_graph(&updated, UsageEcosystem::Rust),
            "the Rust usage graph must survive an edit to a Java file"
        );
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&updated, UsageEcosystem::Jvm),
            "the JVM usage graph must be rebuilt for the edited Java content"
        );
    }

    /// Milestone J (#2449) case (b): an update that rewrites a file with the
    /// same bytes changes no content identity, so every content-keyed cache
    /// answers from what it already holds.
    #[test]
    fn a_no_op_update_reuses_every_content_keyed_workspace_cache() {
        use brokk_bifrost_analysis::analyzer::structural::derived_cache::DerivedLayerAcquisition;

        use brokk_bifrost_analysis::analyzer::structural::derived_cache::DerivedLayerBuildMetrics;

        use brokk_bifrost_analysis::analyzer::structural::derived_cache::DerivedLayerBuildOutcome;

        use brokk_bifrost_analysis::analyzer::structural::derived_cache::DerivedLayerRequest;

        use brokk_bifrost_analysis::analyzer::structural::index::StructuralIndexAcquisition;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheLifecycle;

        use brokk_bifrost_core::cancellation::CancellationToken;

        let (_temp, analyzer) = two_language_analyzer();
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();

        let acquire_layer = |analyzer: &MultiAnalyzer| {
            let content = analyzer
                .workspace_content_identity()
                .expect("a two-language analyzer states a whole-workspace identity");
            let acquisition = analyzer.snapshot_caches.derived_layers().acquire(
                analyzer,
                request,
                content,
                &cancellation,
                || DerivedLayerBuildOutcome::Unavailable {
                    reason: "the test does not need a real topology".to_string(),
                    over_budget: false,
                    rejection_scope: None,
                    metrics: DerivedLayerBuildMetrics::default(),
                },
                || true,
            );
            matches!(acquisition, DerivedLayerAcquisition::Unavailable { .. })
        };
        let structural_lifecycle = |analyzer: &MultiAnalyzer| {
            let providers = analyzer.structural_fact_providers();
            let provider = providers
                .iter()
                .find(|provider| provider.structural_language() == Language::Java)
                .expect("the Java delegate is a structural provider");
            let cache = provider
                .snapshot_structural_index_cache()
                .expect("a built-in provider owns a snapshot index cache");
            match cache.inner().acquire(*provider, &cancellation) {
                StructuralIndexAcquisition::Ready { lifecycle, .. } => lifecycle,
                other => panic!(
                    "the structural index must be acquirable: {}",
                    match other {
                        StructuralIndexAcquisition::Unavailable { reason, .. } =>
                            reason.to_string(),
                        _ => "cancelled".to_string(),
                    }
                ),
            }
        };

        assert!(acquire_layer(&analyzer));
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&analyzer, UsageEcosystem::Jvm)
        );
        assert_eq!(
            brokk_bifrost_analysis::analyzer::structural::index::StructuralIndexLifecycle::Built,
            structural_lifecycle(&analyzer)
        );

        // Rewrite the same bytes: the file's blob identity is unchanged, so no
        // content identity moves even though the analyzer reconciled the file.
        let java = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        let source = std::fs::read_to_string(java.abs_path()).unwrap();
        std::fs::write(java.abs_path(), source).unwrap();
        let updated = analyzer.update(&BTreeSet::from([java]));

        assert_eq!(
            analyzer.workspace_content_identity(),
            updated.workspace_content_identity(),
            "a no-op update must not move the workspace content identity"
        );
        assert!(acquire_layer(&updated));
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Hit,
            acquire_usage_graph(&updated, UsageEcosystem::Jvm)
        );
        assert_eq!(
            brokk_bifrost_analysis::analyzer::structural::index::StructuralIndexLifecycle::Hit,
            structural_lifecycle(&updated)
        );
        let (retained, _) = updated.snapshot_caches.usage_graphs().verdicts().totals();
        assert!(
            retained >= 1,
            "the reuse must be recorded as a retention verdict"
        );
    }

    /// Milestone J (#2449) case (c): a real content change rotates exactly the
    /// identity of the language whose content moved, and the cache records the
    /// typed rebuild verdict rather than silently missing.
    #[test]
    fn a_real_content_change_rotates_the_affected_identity() {
        use brokk_bifrost_analysis::analyzer::invalidation::ArtifactVerdict;

        let (_temp, analyzer) = two_language_analyzer();
        let before = analyzer
            .workspace_content_identities()
            .expect("content identities");
        assert_eq!(2, before.entries().len());

        let rust = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/lib.rs");
        std::fs::write(rust.abs_path(), "pub struct Widget;\npub struct Gauge;\n").unwrap();
        let updated = analyzer.update(&BTreeSet::from([rust]));
        let after = updated
            .workspace_content_identities()
            .expect("content identities");

        assert_ne!(
            before.language(Language::Rust),
            after.language(Language::Rust)
        );
        assert_eq!(
            before.language(Language::Java),
            after.language(Language::Java)
        );
        assert_ne!(before.whole_workspace(), after.whole_workspace());

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;
        acquire_usage_graph(&analyzer, UsageEcosystem::Rust);
        acquire_usage_graph(&updated, UsageEcosystem::Rust);
        let verdicts = updated.snapshot_caches.usage_graphs().verdicts().recent();
        assert!(
            verdicts.iter().any(|verdict| matches!(
                verdict,
                ArtifactVerdict::Invalidated(
                    brokk_bifrost_analysis::analyzer::invalidation::InvalidationReason::NoRetainedArtifact { .. }
                )
            )),
            "the rebuild after a content change must be recorded: {verdicts:?}"
        );
    }
}
