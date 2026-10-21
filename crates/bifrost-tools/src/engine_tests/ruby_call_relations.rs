#[cfg(test)]
mod ruby_extraction_tests {

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::call_span;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::generous_limits;
    #[test]
    fn exact_dispatch_resolves_ruby_safe_navigation_calls_with_blocks() {
        let source = r#"class Service
  def run(value)
  end
end

class Caller
  def call
    service = Service.new
    service&.run(1) { |value| value }
  end
end
"#;
        let call = "service&.run(1) { |value| value }";
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
        assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
        assert_eq!(lookup.targets[0].definition.fq_name(), "Service.run");
        assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
        assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
    }

    #[test]
    fn exact_dispatch_keeps_ruby_dynamic_send_as_an_unresolved_boundary() {
        let source = r#"class Example
  def target
  end

  def caller
    public_send(:target)
  end
end
"#;
        let call = "public_send(:target)";
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::NoDefinition));
        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NoDefinition
            )]
        );
        assert!(
            lookup
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("unsupported_ruby_dynamic_dispatch")),
            "{lookup:#?}"
        );
    }

    #[test]
    fn exact_dispatch_resolves_ruby_operator_methods_from_the_operator_token() {
        let source = r#"class Example
  def +(value)
    value
  end

  def [](index)
    index
  end

  def caller
    self.+(1)
    self.[](2)
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);

        for (call, target) in [("self.+(1)", "Example.+"), ("self.[](2)", "Example.[]")] {
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                token,
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "example.rb"),
                    call_span: call_span(source, call),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
            assert_eq!(lookup.targets.len(), 1, "{call}: {lookup:#?}");
            assert_eq!(lookup.targets[0].definition.fq_name(), target);
            assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
            assert!(lookup.boundaries.is_empty(), "{call}: {lookup:#?}");
        }
    }

    #[test]
    fn exact_dispatch_keeps_ruby_callable_objects_as_a_typed_unresolved_boundary() {
        let source = r#"class Example
  def caller(callable)
    callable.(1)
  end
end
"#;
        let call = "callable.(1)";
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            token,
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "example.rb"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(lookup.status, Some(DefinitionLookupStatus::NoDefinition));
        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NoDefinition
            )]
        );
        assert!(
            lookup
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("unsupported_ruby_callable_object_dispatch")),
            "{lookup:#?}"
        );
    }

    #[test]
    fn ruby_outgoing_relations_keep_attached_block_calls_separate() {
        let source = r#"class Example
  def target
  end

  def nested
  end

  def direct
  end

  def caller
    target() do
      nested()
    end
    direct()
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("example.rb", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let caller = analyzer
            .definitions("Example.caller")
            .next()
            .expect("Ruby caller");

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let relation = CallRelationService::outgoing_bounded(
            analyzer,
            token,
            &caller,
            generous_limits(),
            None,
        );
        let callees = relation
            .sites
            .iter()
            .map(|site| site.callee.fq_name())
            .collect::<Vec<_>>();

        assert_eq!(
            callees,
            vec!["Example.target".to_string(), "Example.direct".to_string()],
            "{relation:#?}"
        );
    }
}
