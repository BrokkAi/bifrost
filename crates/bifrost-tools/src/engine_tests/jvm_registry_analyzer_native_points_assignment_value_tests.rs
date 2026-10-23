#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::native_points::probe_native_assignment_value;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("#5015: Scala term-family binding made constructor write values incomplete")]
    fn scala_constructor_write_keeps_its_observed_frontier_complete() {
        let source = r#"package app
class Base
class Child extends Base
object Use {
  def value(): Base = {
    var current: Base = new Base
    current = new Child
    current
  }
}
"#;
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file("Use.scala", source)
            .build();
        let workspace =
            brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_persisted(
                fixture.project_dyn(),
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            )
            .expect("build constructor-write workspace");
        let request = brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest {
            file: fixture.file("Use.scala"),
            line: Some(8),
            column: Some(5),
            start_byte: None,
            end_byte: None,
        };
        let answer = probe_native_assignment_value(
            workspace.analyzer(),
            &request,
            source,
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        )
        .expect("query constructed write value");
        let BoundedResolution::Complete { value, .. } = answer else {
            panic!("constructor-write query must finish: {answer:?}");
        };
        let mut types = value
            .types
            .iter()
            .map(|ty| ty.fqn.as_str())
            .collect::<Vec<_>>();
        types.sort_unstable();
        assert_eq!(types, ["app.Base", "app.Child"], "{value:?}");
        assert!(value.observed_frontier_complete, "{value:?}");
    }
}
