#[cfg(test)]
mod jvm_registry_tests {
    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::fixture_support::{
        ParsedServiceFixture, callable_definition_at, parsed_service_fixture,
        resolve_positioned_call_at,
    };
    use brokk_bifrost_analysis::analyzer::resolution::{FactResolutionAnswer, SemanticId};
    use brokk_bifrost_core::analyzer::Language;
    type ParsedJavaServiceFixture = ParsedServiceFixture;
    fn parsed_java_service_fixture(source: &str, label: &[u8]) -> ParsedJavaServiceFixture {
        parsed_service_fixture(
            brokk_bifrost_jvm::java::declarations::java_source_facts_for_test(source),
            Language::Java,
            label,
        )
    }
    fn resolve_java_call_at(
        fixture: &ParsedJavaServiceFixture,
        position: usize,
    ) -> (FactResolutionAnswer, SemanticId) {
        resolve_positioned_call_at(
            &fixture.facts,
            &fixture.lexical,
            &fixture.typed,
            &fixture.service,
            position,
            ResolutionNamespace::Callable,
        )
    }
    fn java_callable_definition_at(
        fixture: &ParsedJavaServiceFixture,
        position: usize,
    ) -> SemanticId {
        callable_definition_at(&fixture.facts, &fixture.lexical, position).1
    }

    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

    use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::fixture_support::lowered_semantic_at;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::fixture_support::positioned_site_at;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

    #[cfg(test)]
    #[test]
    fn java_static_call_discharges_implicit_receiver_only_for_static_target() {
        let source = "class A { static int target() { return 1; } static int caller() { return target(); } }";
        let fixture = parsed_java_service_fixture(source, b"java-static-call-no-receiver");
        let declaration_site = positioned_site_at(
            &fixture.facts,
            source.find("target()").expect("target declaration"),
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        );
        let reference_site = positioned_site_at(
            &fixture.facts,
            source.rfind("target()").expect("target call"),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        assert!(fixture.facts.gaps.iter().any(|gap| {
            gap.site == reference_site && gap.kind == ResolutionGapKind::UnsupportedImplicitReceiver
        }));
        let declaration = lowered_semantic_at(
            &fixture.lexical,
            declaration_site,
            LoweredSemanticRole::Definition,
        );
        let reference = lowered_semantic_at(
            &fixture.lexical,
            reference_site,
            LoweredSemanticRole::Reference,
        );
        let reason = fixture
            .lexical
            .gaps()
            .iter()
            .find(|gap| {
                gap.site() == reference_site
                    && gap.origin()
                        == LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedImplicitReceiver,
                        )
            })
            .expect("static callee implicit receiver gap")
            .reason_semantic();
        let answer = fixture
            .service
            .resolve_reference(reference, &CancellationToken::new())
            .expect("preload reads are infallible");

        assert_eq!(answer.binding().targets(), &[declaration]);
        assert!(
            !answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))
        );
    }
    #[cfg(test)]
    #[test]
    fn intrinsic_string_to_value_type_is_definitely_inapplicable() {
        let source = "class A { void f(boolean x) {} void g() { f(\"text\"); } }";
        let fixture = parsed_java_service_fixture(source, b"fixed-call-conversion-unknown");
        let declaration = java_callable_definition_at(
            &fixture,
            source.find("void f").expect("method f") + "void ".len(),
        );
        let (answer, reason) =
            resolve_java_call_at(&fixture, source.rfind("f(\"text\")").expect("call f"));
        assert!(answer.binding().targets().is_empty());
        let [candidate] = answer.callable_candidate_applicability() else {
            panic!("one fixed-shape source declaration remains: {answer:?}");
        };
        assert_eq!(candidate.target(), declaration);
        assert_eq!(candidate.verdict(), ApplicabilityVerdict::Inapplicable);
        assert_eq!(
            candidate.reason(),
            Some(CallableRejectionReason::PrimitiveTypeMismatch)
        );
        assert!(
            !answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason)),
            "known String-to-boolean mismatch is complete evidence: {answer:?}"
        );
    }
}
