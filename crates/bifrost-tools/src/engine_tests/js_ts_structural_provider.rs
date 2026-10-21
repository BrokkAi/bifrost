#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactsCacheOutcome;

    use brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactsLimitedOutcome;

    use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSourceLimitedOutcome;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;

    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::structural::provider::js_ts_tests_support::assert_limited_source_and_syntax_unavailable;
    #[test]
    #[hardwon(
        "fe65bfeaa292: a foreign provider parsed and published facts for files it did not own"
    )]
    fn a_provider_declines_a_file_of_another_language() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let own = ProjectFile::new(root.clone(), "app.ts");
        own.write("export function demo(): void {}\n")
            .expect("write source");
        // A C header this grammar would mis-parse into a flat error tree.
        // bcc's 4.8 MB vmlinux.h cost a Python provider minutes per
        // definition lookup that way, and the facts it published were for a
        // file it never indexed.
        let foreign = ProjectFile::new(root.clone(), "vmlinux.h");
        foreign
            .write("struct s { int a; };\nenum e { E_A = 0, E_B = 1 };\n")
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("TypeScript structural provider");
        let (own_facts, _) = provider.structural_facts_with_outcome(&own);
        let own_facts = own_facts.expect("owning provider facts");
        let own_extractions = provider.structural_extraction_count();
        let (reused_facts, reused_outcome) = provider.structural_facts_with_outcome(&own);
        let reused_facts = reused_facts.expect("reused owning provider facts");
        assert!(Arc::ptr_eq(&reused_facts, &own_facts));
        assert_eq!(reused_outcome, StructuralFactsCacheOutcome::MemoryHit);
        assert!(provider.structural_facts(&foreign).is_none());
        assert!(provider.structural_source(&foreign).is_none());
        assert_limited_source_and_syntax_unavailable(provider, &foreign, usize::MAX);
        assert_eq!(provider.structural_extraction_count(), own_extractions);
    }
    #[test]
    fn limited_source_snapshot_rejects_oversized_input_before_fact_materialization() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "app.ts");
        let source = "export function demo(): void {}\n";
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("TypeScript structural provider");
        let before = provider.structural_extraction_count();

        assert!(matches!(
            provider.structural_source_limited(&file, source.len() - 1, None),
            StructuralSourceLimitedOutcome::Exceeded {
                minimum_source_bytes
            } if minimum_source_bytes >= source.len()
        ));
        assert_eq!(provider.structural_extraction_count(), before);

        let StructuralSourceLimitedOutcome::Available(snapshot) =
            provider.structural_source_limited(&file, source.len(), None)
        else {
            panic!("source should fit its exact byte budget");
        };
        assert_eq!(snapshot.as_ref(), source);
        assert_eq!(provider.structural_extraction_count(), before);
    }
    #[test]
    fn limited_materialization_stops_early_and_caches_only_complete_facts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "app.ts");
        file.write(
            "class Service { run(): void {} }\n\
             export function call(service: Service): void { service.run(); }\n",
        )
        .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("TypeScript structural provider");
        let source = provider.structural_source(&file).expect("source");
        let before = provider.structural_extraction_count();
        let hydrated_before = provider.structural_hydration_count();

        let StructuralFactsLimitedOutcome::Exceeded { minimum_fact_nodes } =
            provider.structural_facts_limited(&file, &source, 1, None)
        else {
            panic!("the canonical manifest must reject the insufficient budget");
        };
        assert!(minimum_fact_nodes > 1);
        assert_eq!(provider.structural_extraction_count(), before);
        assert_eq!(provider.structural_hydration_count(), hydrated_before);

        let complete = provider.structural_facts_limited(&file, &source, usize::MAX, None);
        let StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome: StructuralFactsCacheOutcome::PersistedHydration,
        } = complete
        else {
            panic!("expected complete hydration after the capped attempt");
        };
        assert!(facts.nodes().len() > 1);
        assert_eq!(facts.work_item_count(), minimum_fact_nodes);
        assert_eq!(provider.structural_extraction_count(), before);
        assert_eq!(provider.structural_hydration_count(), hydrated_before + 1);

        assert!(matches!(
            provider.structural_facts_limited(&file, &source, 1, None),
            StructuralFactsLimitedOutcome::Exceeded {
                minimum_fact_nodes: cached_work_items
            } if cached_work_items == minimum_fact_nodes
        ));
        let StructuralFactsLimitedOutcome::Available {
            facts: cached,
            cache_outcome: StructuralFactsCacheOutcome::MemoryHit,
        } = provider.structural_facts_limited(&file, &source, usize::MAX, None)
        else {
            panic!("the complete retry must be cached");
        };
        assert!(Arc::ptr_eq(&facts, &cached));
        assert_eq!(provider.structural_extraction_count(), before);
        assert_eq!(provider.structural_hydration_count(), hydrated_before + 1);
    }
    #[test]
    fn limited_materialization_caps_role_edges_before_caching() {
        let arguments = std::iter::repeat_n("this", 256)
            .collect::<Vec<_>>()
            .join(", ");
        let source = format!(
            "export function f(...args: unknown[]): void {{}}\n\
             f({arguments});\n"
        );

        let measured_temp = tempfile::tempdir().expect("measured temp dir");
        let measured_root = measured_temp.path().canonicalize().expect("measured root");
        let measured_file = ProjectFile::new(measured_root.clone(), "app.ts");
        measured_file.write(&source).expect("write measured source");
        let measured_analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(measured_root, Language::TypeScript));
        let measured_provider = measured_analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("measured TypeScript provider");
        let StructuralFactsLimitedOutcome::Available {
            facts: measured, ..
        } = measured_provider.structural_facts_limited(&measured_file, &source, usize::MAX, None)
        else {
            panic!("unbounded measurement should complete");
        };
        assert!(
            measured.role_count() > measured.nodes().len(),
            "fixture must put most bounded work in raw-span role edges"
        );
        let cap = measured.work_item_count() - 1;
        assert!(
            measured.nodes().len() <= cap,
            "the node arena alone must fit so the role cap is exercised"
        );

        let capped_temp = tempfile::tempdir().expect("capped temp dir");
        let capped_root = capped_temp.path().canonicalize().expect("capped root");
        let capped_file = ProjectFile::new(capped_root.clone(), "app.ts");
        capped_file.write(&source).expect("write capped source");
        let capped_analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(capped_root, Language::TypeScript));
        let capped_provider = capped_analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("capped TypeScript provider");
        let before = capped_provider.structural_extraction_count();
        let hydrated_before = capped_provider.structural_hydration_count();
        assert!(matches!(
            capped_provider.structural_facts_limited(&capped_file, &source, cap, None),
            StructuralFactsLimitedOutcome::Exceeded {
                minimum_fact_nodes
            } if minimum_fact_nodes == cap + 1
        ));
        assert_eq!(capped_provider.structural_extraction_count(), before);
        assert_eq!(
            capped_provider.structural_hydration_count(),
            hydrated_before
        );

        let StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome: StructuralFactsCacheOutcome::PersistedHydration,
        } = capped_provider.structural_facts_limited(&capped_file, &source, usize::MAX, None)
        else {
            panic!("complete retry should materialize and cache every role edge");
        };
        assert_eq!(facts.work_item_count(), measured.work_item_count());
        assert_eq!(capped_provider.structural_extraction_count(), before);
        assert_eq!(
            capped_provider.structural_hydration_count(),
            hydrated_before + 1
        );
        assert!(matches!(
            capped_provider.structural_facts_limited(&capped_file, &source, cap, None),
            StructuralFactsLimitedOutcome::Exceeded {
                minimum_fact_nodes
            } if minimum_fact_nodes == measured.work_item_count()
        ));
        let StructuralFactsLimitedOutcome::Available {
            facts: cached,
            cache_outcome: StructuralFactsCacheOutcome::MemoryHit,
        } = capped_provider.structural_facts_limited(&capped_file, &source, usize::MAX, None)
        else {
            panic!("the complete role projection must be cached");
        };
        assert!(Arc::ptr_eq(&facts, &cached));
        assert_eq!(capped_provider.structural_extraction_count(), before);
        assert_eq!(
            capped_provider.structural_hydration_count(),
            hydrated_before + 1
        );
    }
}
