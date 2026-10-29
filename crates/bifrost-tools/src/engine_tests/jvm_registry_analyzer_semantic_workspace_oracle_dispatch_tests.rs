#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::assert_proven_local_dispatch;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::external_call_identities;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::semantic_call_fixture_for_language;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTarget;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchBoundary;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::UnmaterializedExternalTarget;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::PreparedCallDispatch;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::dispatch_coverage;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::heuristic_external_boundary_without_resolver_authority;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::low_level_boundary;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchTarget;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
    use brokk_bifrost_core::analyzer::model::DispatchExtensibility;
    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;
    use brokk_bifrost_core::analyzer::usages::model::UsageProof;
    use std::sync::Arc;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    #[cfg(test)]
    #[test]
    fn unresolved_canonical_callee_is_model_bindable_but_stays_open() {
        let (_fixture, call) = semantic_call_fixture_for_language(
            Language::Java,
            "Caller.java",
            "class Caller { void call() { com.example.Missing.run(); } }\n",
        );
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("fixture call belongs to its procedure");
        let named = low_level_boundary(
            &CallDispatchBoundaryKind::UnresolvedWithTarget {
                status: DefinitionLookupStatus::NotFound,
                callee_text: "com.example.Missing.run".into(),
                normalized_static_owner: Some("com.example.Missing".into()),
            },
            SemanticLanguage::Standard(Language::Java),
            Some(semantic_call),
            None,
            &[],
        );

        let target = named
            .unmaterialized_external_target()
            .expect("structured callee and semantic call mint a model key");
        assert_eq!(target.owner_fqn(), "com.example.Missing");
        assert_eq!(target.member(), "run");
        assert!(!target.has_receiver());
        assert!(matches!(
            named.kind,
            DispatchBoundaryKind::External(Some(ref locator)) if locator == target.locator()
        ));
        assert!(matches!(named.proof, ProofStatus::Unproven(_)));
        assert!(matches!(
            named.completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert!(
            !heuristic_external_boundary_without_resolver_authority(&named),
            "a resolver-normalized static owner is not syntax-only evidence"
        );
        assert_eq!(
            dispatch_coverage(Some(DefinitionLookupStatus::NotFound), &[named]),
            CandidateCoverage::Open,
            "a bindable model key must not turn an unresolved lookup exhaustive"
        );

        let unnamed = low_level_boundary(
            &CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NotFound),
            SemanticLanguage::Standard(Language::Java),
            Some(semantic_call),
            None,
            &[],
        );
        assert_eq!(unnamed.kind, DispatchBoundaryKind::Unresolved);
        assert!(unnamed.target_locator().is_none());
        assert!(unnamed.unmaterialized_external_target().is_none());
    }
    #[cfg(test)]
    #[test]
    fn kotlin_adapter_proven_local_callback_bypasses_source_rediscovery() {
        let source = "fun caller() { val callback = { 1 }; callback() }\n";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Kotlin, "callback.kt", source);
        let declared_target = match &call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets
        {
            CallableTargetResolution::Proven(CallableTarget::Local(target)) => *target,
            other => panic!("expected one adapter-proven local callback, got {other:?}"),
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
            .expect("adapter-proven Kotlin callback dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("adapter-proven Kotlin local dispatch must be complete: {outcome:?}");
        };

        assert_proven_local_dispatch(&value, declared_target);
        assert!(!value.candidates()[0].provenance().is_empty());
        assert_eq!(budget.used().source_bytes, source.len());
        assert!(session.retained_bytes() >= source.len());
    }
    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0242909d77ed: Java census G09 (2026-10-15): closed super-call evidence must prevent override expansion and close only a materialized target"
    )]
    fn java_nonvirtual_receiver_proof_selects_only_the_superclass_body() {
        let source = "class Base { int value() { return 1; } } class Middle extends Base { int value() { return 2; } } class Leaf extends Middle { int value() { return 3; } int test() { return super.value(); } }";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Java, "SuperOverride.java", source);
        let definitions = fixture.analyzer.analyzer().get_definitions("Middle.value");
        let [definition] = definitions.as_slice() else {
            panic!("one selected superclass declaration: {definitions:?}");
        };
        let oracle = WorkspaceSemanticOracle::with_limits_and_expansion(
            &fixture.analyzer,
            OracleLimits::default(),
            brokk_bifrost_core::analyzer::config::DispatchHierarchyExpansion::CONCRETE_OVERRIDES,
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .resolve_prepared_call(
                &call,
                PreparedCallDispatch {
                    // The native-point regression independently verifies this
                    // source declaration and call-local receiver proof.
                    lookup: CallDispatchLookup {
                        status: Some(DefinitionLookupStatus::Resolved),
                        targets: vec![CallDispatchTarget {
                            definition: definition.clone(),
                            proof: UsageProof::Proven,
                            native_incomplete_source_reason: None,
                        }],
                        call_application: CallApplicationKind::BoundReceiver,
                        dispatch_extensibility: Some(DispatchExtensibility::Closed),
                        ..CallDispatchLookup::default()
                    },
                },
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("nonvirtual source dispatch");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("super invocation must select one complete body: {outcome:?}");
        };
        assert_eq!(value.coverage(), CandidateCoverage::Exhaustive, "{value:?}");
        assert!(value.boundaries().is_empty(), "{value:?}");
        let [candidate] = value.candidates() else {
            panic!("one superclass body and no current-class override: {value:?}");
        };
        assert_eq!(candidate.proof(), &ProofStatus::Proven);
        assert_eq!(candidate.completeness(), &EvidenceCompleteness::Complete);
        assert!(
            candidate
                .target()
                .semantics()
                .locator()
                .declaration()
                .segments()
                .iter()
                .any(|segment| segment.name() == Some("Middle")),
            "{candidate:?}"
        );
    }
    #[cfg(test)]
    /// #1981: Java type qualifiers are syntactic call objects in the raw IR,
    /// but they are not semantic receivers. The definition resolver expands
    /// both the fully-qualified and explicit-import spellings to the same
    /// canonical owner; instance receivers retain their receiver shape.
    #[test]
    fn java_static_type_qualifiers_normalize_without_cross_binding_instances() {
        let source = r#"import java.net.URLDecoder;
import java.lang.String;
class App {
    static void qualified(String raw) {
        java.net.URLDecoder.decode(raw);
    }
    static void imported(String raw) {
        URLDecoder.decode(raw, "UTF-8");
    }
    static void instance(String raw) {
        raw.trim();
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", source),
            vec![
                (
                    "URLDecoder.decode(raw, \"UTF-8\")".to_owned(),
                    Some((
                        "java.net.URLDecoder".to_owned(),
                        "decode".to_owned(),
                        2,
                        false,
                    )),
                ),
                (
                    "java.net.URLDecoder.decode(raw)".to_owned(),
                    Some((
                        "java.net.URLDecoder".to_owned(),
                        "decode".to_owned(),
                        1,
                        false,
                    )),
                ),
                (
                    "raw.trim()".to_owned(),
                    Some(("java.lang.String".to_owned(), "trim".to_owned(), 0, true)),
                ),
            ]
        );
    }
    #[cfg(test)]
    /// A Java type qualifier is structured proof that one receiverless
    /// external call cannot dispatch dynamically. The absent external body
    /// remains a boundary, while an instance receiver retains open dispatch.
    #[test]
    fn java_resolver_proven_static_external_target_closes_only_the_target_set() {
        let source = r#"import java.net.URLDecoder;
import java.lang.String;
class App {
    static void qualified(String raw) {
        java.net.URLDecoder.decode(raw);
    }
    static void imported(String raw) {
        URLDecoder.decode(raw, "UTF-8");
    }
    static void instance(String raw) {
        raw.trim();
    }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Java, &[("App.java", source)]);
        let file = ProjectFile::new(fixture.project_root(), "App.java");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Java semantic materialization")
            .available_value()
            .cloned()
            .expect("Java semantic artifact");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let mut observed = Vec::new();
        for procedure in artifact.procedures() {
            for call in procedure.call_sites() {
                let handle = artifact
                    .procedure_handle(procedure.id())
                    .and_then(|procedure| procedure.call_site_handle(call.id))
                    .expect("scoped call handle");
                let span = procedure
                    .source_mapping(call.source)
                    .expect("call source mapping")
                    .locator
                    .anchor()
                    .span();
                let text = source[span.start_byte() as usize..span.end_byte() as usize].to_owned();
                let mut budget = SemanticBudget::default();
                let outcome = oracle
                    .resolve_call(
                        &handle,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("Java external dispatch runs");
                let complete = matches!(&outcome, SemanticOutcome::Complete { .. });
                let result = outcome
                    .available_value()
                    .expect("Java external dispatch retains a result");
                let resolver_proven_static = result
                    .boundaries()
                    .iter()
                    .filter_map(DispatchBoundary::unmaterialized_external_target)
                    .any(UnmaterializedExternalTarget::resolver_proves_static_call);
                if resolver_proven_static {
                    assert_eq!(
                        result.proven_receiver_shape(),
                        None,
                        "Java static target-set proof must not become Go receiver-shape authority"
                    );
                }
                observed.push((text, complete, result.coverage(), resolver_proven_static));
            }
        }
        observed.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            observed,
            vec![
                (
                    "URLDecoder.decode(raw, \"UTF-8\")".to_owned(),
                    true,
                    CandidateCoverage::Exhaustive,
                    true,
                ),
                (
                    "java.net.URLDecoder.decode(raw)".to_owned(),
                    true,
                    CandidateCoverage::Exhaustive,
                    true,
                ),
                (
                    "raw.trim()".to_owned(),
                    false,
                    CandidateCoverage::Open,
                    false,
                ),
            ]
        );
    }
    #[cfg(test)]
    /// Type-name expansion must fail closed for lexical and import ambiguity.
    /// A workspace type with the same simple name is also not an external
    /// summary owner merely because its requested member is absent.
    #[test]
    fn java_external_static_owner_near_misses_publish_no_identity() {
        let shadowed = r#"import java.net.URLDecoder;
class App {
    static void run(Object URLDecoder, String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", shadowed),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let ambiguous = r#"import a.URLDecoder;
import b.URLDecoder;
class App {
    static void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", ambiguous),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let wildcard_ambiguous = r#"import a.*;
import b.*;
class App {
    static void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", wildcard_ambiguous),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let field_shadowed = r#"import java.net.URLDecoder;
class App {
    Object URLDecoder;
    void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", field_shadowed),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );

        let local_owner = r#"class URLDecoder { }
class App {
    static void run(String raw) {
        URLDecoder.decode(raw);
    }
}
"#;
        assert_eq!(
            external_call_identities(Language::Java, "App.java", local_owner),
            vec![("URLDecoder.decode(raw)".to_owned(), None)]
        );
    }
}
