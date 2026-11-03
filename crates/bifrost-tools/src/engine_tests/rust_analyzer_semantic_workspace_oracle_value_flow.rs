#[cfg(test)]
mod rust_analyzer_semantic_workspace_oracle_value_flow_tests {
    use brokk_bifrost_analysis::analyzer::ProjectFile;
    use brokk_bifrost_analysis::analyzer::semantic::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#8898: procedure openness returned Complete after observing cancellation")]
    fn cancelled_procedure_openness_is_interrupted() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[("app.rs", "fn f() -> i32 { 1 }\n")],
        );
        let workspace = fixture.analyzer.clone();
        let oracle = WorkspaceSemanticOracle::new(&workspace);
        let file = ProjectFile::new(fixture.project_root(), "app.rs");
        let setup_cancellation = CancellationToken::default();
        let mut setup_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut setup_budget, &setup_cancellation),
            )
            .unwrap()
            .available_value()
            .unwrap()
            .clone();
        let procedure = artifact
            .procedure_handle(brokk_bifrost_analysis::analyzer::semantic::ProcedureId::new(0))
            .unwrap();
        let uncancelled = CancellationToken::default();
        let mut uncancelled_budget = SemanticBudget::default();
        let baseline = oracle
            .procedure_openness(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut uncancelled_budget, &uncancelled),
            )
            .unwrap();

        for checks in 1..=64 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut budget = SemanticBudget::default();
            let outcome = oracle
                .procedure_openness(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
            if cancellation.cancel_after_checks_tripped_for_test() {
                assert!(
                    !matches!(outcome, SemanticOutcome::Complete { .. }),
                    "check count {checks} returned Complete after cancellation"
                );
            } else {
                assert_eq!(outcome, baseline, "check count {checks} did not cancel");
            }
        }
    }
}
