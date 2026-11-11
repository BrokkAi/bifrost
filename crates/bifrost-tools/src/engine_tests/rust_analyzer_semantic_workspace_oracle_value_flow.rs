#[cfg(test)]
mod rust_analyzer_semantic_workspace_oracle_value_flow_tests {
    use brokk_bifrost_analysis::analyzer::ProjectFile;
    use brokk_bifrost_analysis::analyzer::semantic::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        DefinitionLookupRequest, DefinitionLookupStatus,
        resolve_definition_batch_with_source_and_cancellation,
    };
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    #[test]
    #[hardwon(
        "#9835: a Rust const generic parameter left the type formals sparse, so shared call-result instantiation panicked on a Go-only density assertion"
    )]
    fn rust_sparse_generic_formals_do_not_panic() {
        let source = r#"
            struct Foo;
            impl Foo { fn marker(&self) {} }
            fn make<'a, const N: usize, T>(value: T) -> T { value }
            fn caller() {
                let valid_i32 = make::<1, i32>(7);
                let _next = valid_i32.to_string();
                make::<1, Foo>(Foo).marker();
                make::<Foo>(Foo).marker();
            }
        "#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("app.rs", source)]);
        let workspace = fixture.analyzer.clone();
        let oracle = WorkspaceSemanticOracle::new(&workspace);
        let file = ProjectFile::new(fixture.project_root(), "app.rs");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .unwrap()
            .clone();
        for candidate in artifact.procedures() {
            let procedure = artifact.procedure_handle(candidate.id()).unwrap();
            let mut budget = SemanticBudget::default();
            let _ = oracle
                .procedure_openness(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
        }
        let marker_call = source.find(".marker()").unwrap() + 1;
        let outcomes = resolve_definition_batch_with_source_and_cancellation(
            fixture.analyzer.analyzer(),
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(marker_call),
                end_byte: Some(marker_call + "marker".len()),
            }],
            file,
            Arc::from(source),
            &cancellation,
        );
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, DefinitionLookupStatus::Resolved);
        assert!(
            outcomes[0]
                .definitions
                .iter()
                .any(|unit| unit.fq_name() == "Foo.marker"),
            "{outcomes:?}"
        );
    }

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
