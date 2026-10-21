#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::SemanticWork;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::runtime_values::RuntimeKeyedReadFilter;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::runtime_values::RuntimeReadLimitation;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    use brokk_bifrost_core::analyzer::model::Range;
    #[test]
    fn runtime_query_budget_exhaustion_does_not_certify_absence() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::JavaScript,
            &[("probe.js", "const value = process.argv[2];")],
        );
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::uniform(1).unwrap();
        let file = ProjectFile::new(fixture.project_root(), "probe.js");
        let range = Range {
            start_byte: 14,
            end_byte: 29,
            start_line: 0,
            end_line: 0,
        };
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .runtime_keyed_read_at_source(
                &file,
                range,
                &RuntimeKeyedReadFilter::default(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("budget interruption is a semantic outcome");
        assert!(matches!(outcome, SemanticOutcome::ExceededBudget { .. }));
        assert!(
            outcome
                .available_value()
                .is_none_or(|result| result.endpoints.is_empty() && !result.conclusive_exclusion)
        );
    }
    #[test]
    fn absent_runtime_activation_is_not_an_exact_or_clean_source() {
        let source = "function run() { return process.env.DFB_INPUT; }";
        let fixture =
            AnalyzerFixture::new_for_language(Language::JavaScript, &[("probe.js", source)]);
        let file = ProjectFile::new(fixture.project_root(), "probe.js");
        let start = source.find("process.env.DFB_INPUT").unwrap();
        let range = Range {
            start_byte: start,
            end_byte: start + "process.env.DFB_INPUT".len(),
            start_line: 0,
            end_line: 0,
        };
        let filter = RuntimeKeyedReadFilter {
            runtime: "node".into(),
            global: "process".into(),
            container: "env".into(),
            property: Some("DFB_INPUT".into()),
            pristine_input: true,
            ..RuntimeKeyedReadFilter::default()
        };
        let mut budget = SemanticBudget::default();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .runtime_keyed_read_at_source(
                &file,
                range,
                &filter,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("runtime candidate query runs");
        assert!(
            !outcome.is_complete(),
            "missing activation must not certify absence"
        );
        let result = outcome
            .available_value()
            .expect("typed runtime limitation is retained");
        assert!(result.endpoints.is_empty());
        assert!(!result.conclusive_exclusion);
        assert!(
            result
                .limitations
                .contains(&RuntimeReadLimitation::ActivationMissing)
        );
    }
    #[test]
    fn cancelled_runtime_query_does_not_materialize_or_publish() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::JavaScript,
            &[("probe.js", "const value = process.argv[2];")],
        );
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        cancellation.cancel();
        let mut budget = SemanticBudget::default();
        let file = ProjectFile::new(fixture.project_root(), "probe.js");
        let range = Range {
            start_byte: 14,
            end_byte: 29,
            start_line: 0,
            end_line: 0,
        };
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .runtime_keyed_read_at_source(
                &file,
                range,
                &RuntimeKeyedReadFilter::default(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("cancellation is semantic, not provider failure");
        assert!(
            matches!(outcome, SemanticOutcome::Cancelled { partial: None, work } if work == SemanticWork::default())
        );
    }
}
