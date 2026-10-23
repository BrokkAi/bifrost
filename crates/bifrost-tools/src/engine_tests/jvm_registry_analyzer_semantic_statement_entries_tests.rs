#[cfg(test)]
mod jvm_registry_tests {

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureKind;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::statement_entries::StatementVerdict;
    use brokk_bifrost_analysis::analyzer::semantic::statement_entries::statement_assessments;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("dad21e7d6133: Java body reachability omitted nested statement blocks")]
    fn java_statement_entries_exclude_the_procedure_body_but_retain_nested_blocks() {
        let source = r#"class Sample {
  Sample() {}
  void nested(boolean flag) { if (flag) {} }
}"#;
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Sample.java", source)
            .build();
        let file = project.file("src/Sample.java");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Java semantics materialize")
            .available_value()
            .cloned()
            .expect("Java artifact available");
        let procedure = |kind, name| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure.kind() == kind
                        && procedure
                            .locator()
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("{kind:?} {name} exists"))
        };

        let constructor = statement_assessments(
            &analyzer,
            &procedure(ProcedureKind::Constructor, "Sample"),
            None,
        );
        assert!(constructor.complete, "{:?}", constructor.reason);
        assert!(constructor.rows.is_empty(), "{:?}", constructor.rows);

        let nested =
            statement_assessments(&analyzer, &procedure(ProcedureKind::Method, "nested"), None);
        assert!(nested.complete, "{:?}", nested.reason);
        let blocks = nested
            .rows
            .iter()
            .filter(|row| row.kind == "block")
            .collect::<Vec<_>>();
        assert_eq!(blocks.len(), 1, "{:?}", nested.rows);
        assert_eq!(blocks[0].verdict, StatementVerdict::Reachable);
    }
}
