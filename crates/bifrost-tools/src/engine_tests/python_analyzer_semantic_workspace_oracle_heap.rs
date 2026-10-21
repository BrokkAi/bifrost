#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::oracle::heap::EscapeStatus;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::AbstractObjectIdentity;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::common::Interruption;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::common::WorkStager;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::InterruptionOrProvider;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::object_escape_status;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    use brokk_bifrost_core::cancellation::CancellationToken;
    #[test]
    fn escape_proof_shares_only_paid_caller_source() {
        let source = "def inspect(value):\n    pass\n\ndef caller():\n    items = [1]\n    inspect(items)\n    inspect(items)\n    items[0] = 2\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Python, &[("calls.py", source)]);
        let file = ProjectFile::new(fixture.project_root(), "calls.py");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("materialization runs")
            .available_value()
            .cloned()
            .expect("artifact");
        let allocation = artifact
            .procedures()
            .iter()
            .find_map(|semantics| {
                let allocation = semantics.allocations().first()?;
                artifact
                    .procedure_handle(semantics.id())?
                    .allocation_handle(allocation.id)
            })
            .expect("list allocation");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let identity = AbstractObjectIdentity::Allocation(allocation);
        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = source.len() - 1;
        let mut tight = SemanticBudget::new(limits).expect("positive source limit");
        let request = SemanticRequest::new(&mut tight, &cancellation);
        let mut failed = WorkStager::new(&request);
        assert!(matches!(
            object_escape_status(
                &oracle,
                &identity,
                &OracleCallContext::empty(),
                &mut failed,
                &cancellation
            ),
            Err(InterruptionOrProvider::Interruption(Interruption::Budget(
                _
            )))
        ));
        assert_eq!(tight.used().source_bytes, 0, "failed work is not committed");

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let mut cancelled_budget = SemanticBudget::default();
        let request = SemanticRequest::new(&mut cancelled_budget, &cancelled);
        let mut interrupted = WorkStager::new(&request);
        assert!(matches!(
            object_escape_status(
                &oracle,
                &identity,
                &OracleCallContext::empty(),
                &mut interrupted,
                &cancelled
            ),
            Err(InterruptionOrProvider::Interruption(
                Interruption::Cancelled
            ))
        ));
        assert_eq!(interrupted.work.source_bytes, 0);

        let mut budget = SemanticBudget::default();
        let request = SemanticRequest::new(&mut budget, &cancellation);
        let mut staged = WorkStager::new(&request);
        let escape = object_escape_status(
            &oracle,
            &identity,
            &OracleCallContext::empty(),
            &mut staged,
            &cancellation,
        )
        .unwrap_or_else(|failure| match failure {
            InterruptionOrProvider::Interruption(error) => {
                panic!("escape proof interrupted: {error:?}")
            }
            InterruptionOrProvider::Provider(error) => panic!("escape provider failed: {error:?}"),
        });
        assert_eq!(escape, EscapeStatus::DoesNotEscape);
        assert_eq!(
            staged.work.source_bytes,
            source.len(),
            "one exact caller source is sufficient for both nonpublishing calls"
        );
    }
}
