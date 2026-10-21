#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactsCacheOutcome;

    use brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactsLimitedOutcome;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::gitblob::test_repo::commit_all;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::gitblob::test_repo::init_repo;
    use std::sync::Arc;
    const RUST_READY_SOURCE: &str =
        "fn helper(value: i32) -> i32 { value + 1 }\nfn main() { helper(1); }\n";

    #[test]
    fn ready_rust_bounded_reads_use_persisted_or_ephemeral_facts_without_extraction() {
        for persisted in [false, true] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("src/lib.rs", RUST_READY_SOURCE)
                .build();
            if persisted {
                let repository = init_repo(fixture.root());
                commit_all(&repository, "ready Rust source");
            }
            let project: Arc<dyn Project> = fixture.project_dyn();
            let workspace = if persisted {
                WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                    Arc::clone(&project),
                    AnalyzerConfig::default(),
                )
                .expect("persisted Rust workspace should build")
            } else {
                WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                    .expect("ephemeral Rust workspace should build")
            };
            let file = fixture.file("src/lib.rs");
            let provider = workspace
                .analyzer()
                .structural_fact_providers()
                .into_iter()
                .next()
                .expect("Rust structural provider");
            let source = provider.structural_source(&file).expect("Rust source");
            let before = provider.structural_extraction_count();

            let StructuralFactsLimitedOutcome::Available {
                facts,
                cache_outcome,
            } = provider.structural_facts_limited(&file, &source, usize::MAX, None)
            else {
                panic!("ready canonical Rust facts should satisfy an unbounded read");
            };
            assert_eq!(facts.source(), RUST_READY_SOURCE);
            assert!(facts.work_item_count() > 0);
            assert_ne!(cache_outcome, StructuralFactsCacheOutcome::Extracted);
            assert_eq!(provider.structural_extraction_count(), before);
        }
    }

    #[test]
    fn dirty_rust_structural_cache_is_exact_source_keyed_across_a_b_a() {
        let source_a = "fn same() {}\n";
        let source_b = "fn same() {}\nfn extra() { same(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", source_a)
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral Rust workspace should build");
        let file = fixture.file("src/lib.rs");
        let base_provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("Rust structural provider");
        let (facts_a, _) = base_provider.structural_facts_with_outcome(&file);
        let facts_a = facts_a.expect("initial source A facts");
        assert_eq!(facts_a.source(), source_a);
        let a_nodes = facts_a.nodes().len();
        let before_b = base_provider.structural_extraction_count();

        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), source_b.to_owned()));
        let workspace_b = workspace.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        let provider_b = workspace_b
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("Rust structural provider for source B");
        let (facts_b, outcome_b) = provider_b.structural_facts_with_outcome(&file);
        let facts_b = facts_b.expect("dirty source B facts");
        assert_eq!(facts_b.source(), source_b);
        assert!(facts_b.nodes().len() > a_nodes);
        assert_eq!(outcome_b, StructuralFactsCacheOutcome::Extracted);
        assert_eq!(provider_b.structural_extraction_count(), before_b + 1);
        drop(workspace_b);

        assert!(overlay.set(file.abs_path(), source_a.to_owned()));
        let workspace_a = workspace.clone_with_project(overlay as Arc<dyn Project>);
        let provider_a = workspace_a
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("Rust structural provider for source A");
        let (facts_again, outcome_again) = provider_a.structural_facts_with_outcome(&file);
        let facts_again = facts_again.expect("source A facts after source B");
        assert_eq!(facts_again.source(), source_a);
        assert_eq!(facts_again.nodes().len(), a_nodes);
        assert_ne!(outcome_again, StructuralFactsCacheOutcome::Extracted);
        assert_eq!(provider_a.structural_extraction_count(), before_b + 1);
    }

    #[test]
    fn bounded_rust_budget_and_cancellation_do_not_parse_a_ready_file() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", RUST_READY_SOURCE)
            .build();
        let repository = init_repo(fixture.root());
        commit_all(&repository, "bounded Rust source");
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("persisted Rust workspace should build");
        let file = fixture.file("src/lib.rs");
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("Rust structural provider");
        let source = provider.structural_source(&file).expect("Rust source");
        let before = provider.structural_extraction_count();

        assert!(matches!(
            provider.structural_facts_limited(&file, &source, 0, None),
            StructuralFactsLimitedOutcome::Exceeded {
                minimum_fact_nodes
            } if minimum_fact_nodes > 0
        ));
        assert_eq!(provider.structural_extraction_count(), before);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            provider.structural_facts_limited(&file, &source, usize::MAX, Some(&cancellation)),
            StructuralFactsLimitedOutcome::Cancelled
        ));
        assert_eq!(provider.structural_extraction_count(), before);
    }
}
