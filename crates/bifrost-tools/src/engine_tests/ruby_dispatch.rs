#[cfg(test)]
mod ruby_extraction_tests {

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTarget;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchCandidate;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::DispatchQuality;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;

    use brokk_bifrost_analysis::analyzer::semantic::OracleLimits;

    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::ProcedureHandle;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureKind;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::ProcedureRangeLookupStatus;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapKind;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::assert_proven_local_dispatch;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::procedure_matches_definition;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::procedures_for_definition_with_limits;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::proven_static_target_discharges_gap;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::semantic_call_fixture_for_language;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    #[test]
    fn ruby_adapter_proven_local_lambda_bypasses_source_rediscovery() {
        let source = "def caller\n  local = ->(value) { value }\n  local.(1)\nend\n";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Ruby, "callback.rb", source);
        let declared_target = match call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => target,
            ref other => panic!("expected one adapter-proven Ruby lambda, got {other:?}"),
        };
        let artifact = Arc::clone(call.procedure().artifact());
        let mut session = fixture
            .analyzer
            .semantic_oracle_provider()
            .prepare_call_dispatch_session(artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = session
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("adapter-proven Ruby lambda dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven Ruby local dispatch must be complete: {outcome:?}");
        };

        assert_proven_local_dispatch(&value, declared_target);
    }

    #[test]
    fn declaration_procedure_lookup_excludes_nested_same_named_ruby_method() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Ruby,
            &[(
                "nested.rb",
                "def target(value)\n  def target(value)\n    value\n  end\n  value\nend\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "nested.rb");
        let analyzer = fixture.analyzer.analyzer();
        let definition = analyzer
            .get_definitions("target")
            .into_iter()
            .max_by_key(|definition| {
                analyzer
                    .ranges(definition)
                    .into_iter()
                    .map(|range| range.end_byte.saturating_sub(range.start_byte))
                    .max()
                    .unwrap_or_default()
            })
            .expect("outer target definition");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Ruby semantic materialization")
            .available_value()
            .cloned()
            .expect("Ruby semantic artifact");
        let matching_procedures = artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure_matches_definition(procedure, &definition))
            .count();
        assert_eq!(
            matching_procedures, 2,
            "fixture must contain outer and nested same-name procedures"
        );

        let lookup = procedures_for_definition_with_limits(
            analyzer,
            &definition,
            &artifact,
            usize::MAX,
            &cancellation,
        );

        assert_eq!(lookup.status, ProcedureRangeLookupStatus::Complete);
        assert_eq!(lookup.handles.len(), 1, "nested same-name procedure leaked");
        assert_eq!(
            lookup.handles[0]
                .semantics()
                .locator()
                .anchor()
                .span()
                .start_byte(),
            0,
            "the outer declaration must resolve to the outer procedure"
        );
    }

    /// Ruby lowers every `def` as `ProcedureKind::Method`, including a
    /// top-level one that owns no receiver (#2637). The resolver-proven arm
    /// therefore decides on the declaration path: a file-scope `def` has no
    /// owning class or module and so no override set the proven candidate
    /// list could be missing, while a `def` in a class body does.
    #[test]
    fn file_scope_method_candidate_discharges_a_dispatch_gap_but_a_member_does_not() {
        const SOURCE: &str = r#"def free_target
  "value"
end

class Owner
  def member_target
    "value"
  end
end

def run
  free_target
end
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, &[("dispatch.rb", SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "dispatch.rb");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Ruby semantic materialization")
            .available_value()
            .cloned()
            .expect("Ruby semantic artifact");
        let handle_named = |name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("procedure {name} is materialized"))
        };
        let caller = handle_named("run");
        let candidate = |target: ProcedureHandle| {
            vec![
                DispatchCandidate::new(
                    target,
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                    std::iter::empty(),
                    OracleLimits::default(),
                )
                .expect("an empty dispatch draft fits every positive provenance limit"),
            ]
        };
        let gap = caller
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.capability == SemanticCapability::DynamicDispatch
                    && gap.kind == SemanticGapKind::Unknown
            })
            .expect("Ruby publishes an unconditional per-call dynamic-dispatch gap");
        assert_eq!(
            handle_named("free_target").semantics().kind(),
            ProcedureKind::Method,
            "the fixture is only meaningful while Ruby lowers a top-level def as a method"
        );

        let discharges = |candidates: &[DispatchCandidate]| {
            proven_static_target_discharges_gap(
                &caller,
                &CallableTargetResolution::Unknown,
                true,
                candidates,
                &[],
                true,
                DispatchQuality::Complete,
                gap,
            )
        };
        assert!(discharges(&candidate(handle_named("free_target"))));
        assert!(!discharges(&candidate(handle_named("member_target"))));
    }
}
