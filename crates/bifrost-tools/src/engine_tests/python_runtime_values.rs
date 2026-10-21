#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::runtime_values::RuntimeAccessKey;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::runtime_values::RuntimeReadLimitation;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_semantic::analyzer::semantic::ir::ProcedureKind;

    use crate::analyzer::semantic::SemanticBudget;

    use crate::analyzer::semantic::SemanticExecutionBudget;

    use crate::analyzer::semantic::SemanticOutcome;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("#3534: repeated Python procedures caused repeated source parsing")]
    fn many_python_procedures_share_syntax_but_keep_distinct_runtime_candidates() {
        let mut source = String::from("import sys\n");
        for index in 0..64 {
            source.push_str(&format!(
                "def read_{index}():\n    return sys.argv[{index}]\n"
            ));
        }
        let fixture = AnalyzerFixture::new_for_language(Language::Python, &[("probe.py", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "probe.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Python semantic materialization")
            .available_value()
            .cloned()
            .expect("Python artifact");
        let mut limits = SemanticWork::default_limits();
        limits.source_bytes = 64 * source.len();
        let mut budget = SemanticBudget::new(limits).unwrap();
        let mut indices = Vec::new();
        for procedure in artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure.kind() == ProcedureKind::Function)
        {
            let handle = artifact.procedure_handle(procedure.id()).unwrap();
            let oracle = fixture.analyzer.semantic_oracle_provider();
            // Logical work is replayed, but only the first request parses.
            let execution = SemanticExecutionBudget::new(1);
            let outcome = oracle
                .runtime_reads_for_procedure(
                    &handle,
                    &mut SemanticRequest::with_execution_budget(
                        &mut budget,
                        &cancellation,
                        &execution,
                    ),
                )
                .expect("procedure runtime candidates");
            assert!(
                matches!(outcome, SemanticOutcome::Unproven { .. }),
                "{outcome:?}"
            );
            let result = outcome.available_value().unwrap();
            assert!(
                result
                    .limitations
                    .contains(&RuntimeReadLimitation::ActivationMissing),
                "{result:?}"
            );
            assert!(result.endpoints.is_empty());
            assert_eq!(result.candidates.len(), 1);
            let Some(RuntimeAccessKey::Index(index)) = result.candidates[0].key else {
                panic!("expected distinct argv index: {result:?}");
            };
            indices.push(index);
        }
        indices.sort_unstable();
        assert_eq!(indices, (0..64).collect::<Vec<u128>>());
        assert_eq!(budget.used().source_bytes, 64 * source.len());
        assert_eq!(budget.charged_artifact_count(), 1);
    }
}
