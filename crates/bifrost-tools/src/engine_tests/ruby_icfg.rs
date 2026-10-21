#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapKind;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapSubject;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureKind;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("2f4cb01c5326: Ruby constructor dispatch retained stale builtin gaps")]
    fn ruby_constructor_is_supported_without_a_stale_call_gap() {
        let source = r#"
class Widget
  def initialize
    helper
  end

  def helper
    1
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::Ruby,
            &[("widget.rb", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "widget.rb");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Ruby materialization")
            .available_value()
            .cloned()
            .expect("Ruby artifact");
        let constructor = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Constructor)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("Ruby initialize procedure");

        assert!(!constructor.semantics().gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && gap.capability == SemanticCapability::Calls
                && gap.kind == SemanticGapKind::Unsupported
        }));
        assert!(
            brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::scoped_procedure_dispatch_gap(
                &constructor
            )
            .is_none()
        );
    }
}
