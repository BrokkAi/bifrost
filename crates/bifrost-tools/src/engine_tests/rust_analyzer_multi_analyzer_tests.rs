#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::CodeUnitIndex;

    use brokk_bifrost_analysis::IAnalyzer;

    use std::sync::Arc;

    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::definition_lookup::DefinitionLanguageScope;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::definition_lookup::RelationalBatchOutcome;

    use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionRequest;

    use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionValue;

    use crate::engine_tests::rust_multi_analyzer_support::two_language_analyzer;

    use brokk_bifrost_core::analyzer::RelationalDefinitionQuery;
    use brokk_bifrost_core::analyzer::RelationalName;

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn update_with_only_irrelevant_files_retains_snapshot_caches() {
        let (_temp, analyzer) = two_language_analyzer();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        let readme = ProjectFile::new(analyzer.project().root().to_path_buf(), "README.md");
        let updated = analyzer.update(&BTreeSet::from([readme]));

        assert_eq!(
            updated.test_hooks().full_declaration_scan_count_for_test(),
            0
        );
        assert!(
            Arc::ptr_eq(&analyzer.snapshot_caches, &updated.snapshot_caches),
            "an update touching no analyzed file must keep the workspace derived-layer caches"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn update_touching_an_analyzed_file_carries_the_content_keyed_caches_forward() {
        let (_temp, analyzer) = two_language_analyzer();
        let source = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        let updated = analyzer.update(&BTreeSet::from([source]));

        // The container is new because the semantic-model publication inside it
        // is snapshot-scoped, but the two content-keyed caches ride the update
        // (#2449): a value keyed by content an edit did not touch stays exact.
        assert!(!Arc::ptr_eq(
            &analyzer.snapshot_caches,
            &updated.snapshot_caches
        ));
        assert!(std::ptr::eq(
            analyzer.snapshot_caches.derived_layers(),
            updated.snapshot_caches.derived_layers()
        ));
        assert!(std::ptr::eq(
            analyzer.snapshot_caches.usage_graphs(),
            updated.snapshot_caches.usage_graphs()
        ));
    }

    #[test]
    fn relational_workspace_batch_merges_language_projections() {
        let (_temp, analyzer) = two_language_analyzer();
        let root = analyzer.project().root().to_path_buf();
        let java_file = ProjectFile::new(root.clone(), "src/App.java");
        let rust_file = ProjectFile::new(root, "src/lib.rs");
        let java = analyzer
            .declarations(&java_file)
            .into_iter()
            .find(CodeUnit::is_class)
            .expect("Java class declaration");
        let rust = analyzer
            .declarations(&rust_file)
            .into_iter()
            .find(CodeUnit::is_class)
            .expect("Rust struct declaration");
        let requests = [
            RelationalDefinitionRequest {
                ordinal: 9,
                language_scope: DefinitionLanguageScope::Workspace,
                name: RelationalName::stable(java.fq().clone()),
                query: RelationalDefinitionQuery::ExactName,
            },
            RelationalDefinitionRequest {
                ordinal: 4,
                language_scope: DefinitionLanguageScope::Workspace,
                name: RelationalName::stable(rust.fq().clone()),
                query: RelationalDefinitionQuery::ExactName,
            },
        ];

        let RelationalBatchOutcome::Complete(results) = analyzer.relational_definition_batch(
            &requests,
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        ) else {
            panic!("mixed relational batch should complete");
        };
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ordinal, 9);
        assert_eq!(results[1].ordinal, 4);
        assert_eq!(
            results[0].value,
            RelationalDefinitionValue::Definitions(vec![java])
        );
        assert_eq!(
            results[1].value,
            RelationalDefinitionValue::Definitions(vec![rust])
        );
    }
}
