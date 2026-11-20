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
    fn family_call(
        workspace: &brokk_bifrost_analysis::WorkspaceAnalyzer,
    ) -> brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle {
        let file = ProjectFile::new(workspace.analyzer().project().root(), "Caller.java");
        let mut budget = SemanticBudget::default();
        let cancellation = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .unwrap()
            .clone();
        brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::first_call_in_artifact(&artifact)
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "790dbdae8bb6: family inputs accepted independently weakened transfer evidence"
    )]
    fn java_dispatch_family_membership_inventory_and_receipt_boundary() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::capture_query_reads;
        use brokk_bifrost_analysis::analyzer::semantic::{
            CallTransferFamilyProjection, CallTransferInputStatus, DispatchFamilyMemberBody,
            IcfgProvider, WorkspaceIcfgProvider,
        };
        use brokk_bifrost_analysis::analyzer::workspace_authority::workspace_memo_attribution;
        use brokk_bifrost_core::analyzer::config::DispatchHierarchyExpansion;
        for (base, a, b, expansion, certified, runtime_count, candidate_count) in [
            (
                "class Base { public void close() {} }",
                "class A extends Base { public void close() {} }",
                "class B extends Base { public void close() {} }",
                DispatchHierarchyExpansion::OFF,
                false,
                0,
                1,
            ),
            (
                "class Base { public void close() {} }",
                "class A extends Base { public void close() {} }",
                "class B extends Base { public void close() {} }",
                DispatchHierarchyExpansion::CONCRETE_OVERRIDES,
                true,
                3,
                3,
            ),
            (
                "interface Base { void close(); }",
                "class A implements Base { public void close() {} }",
                "class B implements Base { public void close() {} }",
                DispatchHierarchyExpansion::OFF,
                true,
                2,
                2,
            ),
            (
                "abstract class Base { public abstract void close(); }",
                "class A extends Base { public void close() {} }",
                "class B extends Base { public native void close(); }",
                DispatchHierarchyExpansion::OFF,
                true,
                2,
                1,
            ),
            (
                "interface Base { void close(); }",
                "class A implements Base { public void close() {} }",
                "class B extends Missing implements Base { public native void close(); }",
                DispatchHierarchyExpansion::OFF,
                false,
                0,
                1,
            ),
            (
                "interface Base { void close(); }",
                "class A implements Base { public void close() {} }",
                "class B extends Missing implements Base { public void close() {} }",
                DispatchHierarchyExpansion::OFF,
                false,
                0,
                2,
            ),
            (
                "class Base { public native void close(); }",
                "class A extends Base { public void close() {} }",
                "class B extends Base { public void close() {} }",
                DispatchHierarchyExpansion::CONCRETE_OVERRIDES,
                false,
                0,
                0,
            ),
            (
                "class Base { public native void close(); }",
                "class A {}",
                "class B {}",
                DispatchHierarchyExpansion::OFF,
                true,
                1,
                0,
            ),
            (
                "interface Base { void close(); }",
                "class A {}",
                "class B {}",
                DispatchHierarchyExpansion::OFF,
                true,
                0,
                0,
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Java)
                .file("Base.java", base)
                .file("A.java", a)
                .file("B.java", b)
                .file(
                    "Caller.java",
                    "class Caller { void call(Base value) { value.close(); value.close(); } }",
                )
                .build();
            let workspace = project.certified_workspace_analyzer(Default::default());
            let call = family_call(&workspace);
            let oracle = WorkspaceSemanticOracle::with_limits_and_expansion(
                &workspace,
                OracleLimits::default(),
                expansion,
            );
            let mut budget = SemanticBudget::default();
            let cancellation = CancellationToken::default();
            let (outcome, reads) = capture_query_reads(workspace.analyzer(), || {
                oracle
                    .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                    .unwrap()
            });
            let result = outcome
                .available_value()
                .expect("known dispatch is retained");
            assert_eq!(
                result.candidates().len(),
                candidate_count,
                "{base}: {outcome:?}"
            );
            let family = result
                .family()
                .expect("virtual call retains typed family attempt");
            assert_eq!(
                family.membership().is_some(),
                certified,
                "{base}/{a}/{b}: inputs={:?}; reads={:?}",
                family.inputs(),
                reads.unordered_keys()
            );
            if let Some(membership) = family.membership() {
                assert_eq!(membership.call(), &call);
                assert_eq!(membership.members().len(), runtime_count, "{family:?}");
                let (_, replayed) = capture_query_reads(workspace.analyzer(), || {
                    membership.replay(&workspace_memo_attribution(&workspace))
                });
                let mut cold_keys = reads.unordered_keys();
                let mut replayed_keys = replayed.unordered_keys();
                cold_keys.sort();
                replayed_keys.sort();
                assert_eq!(
                    cold_keys, replayed_keys,
                    "witness replays all producer premises"
                );
                assert!(
                    !replayed_keys.iter().any(|key| matches!(
                        key,
                        brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                            kind: brokk_bifrost_analysis::analyzer::LookupKind::ProcedureDispatch,
                            ..
                        }
                    )),
                    "the witness must not read its own response"
                );
                assert!(family.retained_bytes() > std::mem::size_of_val(family));
                let mut census = brokk_bifrost_analysis::analyzer::semantic::service::ArtifactRetentionCensus::default();
                family.retained_artifacts(&mut census);
                assert!(census.retained_bytes() >= family.retained_bytes() as u64);
                assert!(
                    family
                        .inputs()
                        .iter()
                        .filter(|input| matches!(
                            input.body(),
                            DispatchFamilyMemberBody::Materialized(_)
                        ))
                        .all(|input| input.proof() == &ProofStatus::Proven
                            && input.completeness() == &EvidenceCompleteness::Complete)
                );
                if base.contains("native") || b.contains("native") {
                    assert!(family.inputs().iter().any(|input| matches!(
                        input.body(),
                        DispatchFamilyMemberBody::Unavailable
                    ) && matches!(
                        input.completeness(),
                        EvidenceCompleteness::Partial(_)
                    )));
                    if !expansion.concrete_overrides {
                        let projected = WorkspaceIcfgProvider::new(&workspace)
                            .call_transfers(
                                call.procedure(),
                                call.id(),
                                &mut SemanticRequest::new(
                                    &mut SemanticBudget::default(),
                                    &cancellation,
                                ),
                            )
                            .unwrap();
                        let set = projected.available_value().unwrap();
                        let inputs = set
                            .family_inputs
                            .as_ref()
                            .expect("known unavailable member is retained");
                        assert_eq!(inputs.members().len(), runtime_count);
                        assert!(inputs.members().iter().any(|member| member.projection()
                            == CallTransferFamilyProjection::BodyUnavailable
                            && member.arity().is_none()));
                        assert!(!inputs.applies_to(&call, set), "{inputs:?}; {set:?}");
                    }
                }
                // Raw may-target proof is unchanged by complete enumeration.
                if base.starts_with("interface") || base.starts_with("abstract") {
                    assert!(result.candidates().iter().all(|candidate| matches!(
                        candidate.proof(),
                        ProofStatus::Unproven(_)
                    ) && matches!(
                        candidate.completeness(),
                        EvidenceCompleteness::Partial(_)
                    )));
                }
                if runtime_count == 2 && candidate_count == 2 {
                    let pool = oracle.prepare_workspace_dispatch_pool();
                    for _ in 0..2 {
                        let (pooled, observed) = capture_query_reads(workspace.analyzer(), || {
                            pool.resolve_call(
                                &call,
                                &mut SemanticRequest::new(
                                    &mut SemanticBudget::default(),
                                    &cancellation,
                                ),
                            )
                            .unwrap()
                        });
                        let pooled_family = pooled.available_value().unwrap().family().unwrap();
                        assert_eq!(family, pooled_family);
                        let (_, receipt_reads) = capture_query_reads(workspace.analyzer(), || {
                            pooled_family
                                .membership()
                                .unwrap()
                                .replay(&workspace_memo_attribution(&workspace))
                        });
                        let mut observed = observed.unordered_keys();
                        let mut receipt_reads = receipt_reads.unordered_keys();
                        observed.sort();
                        receipt_reads.sort();
                        assert_eq!(observed, receipt_reads);
                    }
                    // A receipt-only budget refusal preserves all paid bodies
                    // and leaves membership explicitly unavailable.
                    let mut reference_budget = SemanticBudget::default();
                    let reference = oracle
                        .resolve_call(
                            &call,
                            &mut SemanticRequest::new(&mut reference_budget, &cancellation),
                        )
                        .unwrap();
                    assert!(
                        reference
                            .available_value()
                            .unwrap()
                            .family()
                            .unwrap()
                            .membership()
                            .is_some()
                    );
                    let mut limits = SemanticBudget::default().limits();
                    limits.owned_text_bytes = reference_budget.resident().owned_text_bytes - 1;
                    let mut limited_budget = SemanticBudget::new(limits).unwrap();
                    let limited = oracle
                        .resolve_call(
                            &call,
                            &mut SemanticRequest::new(&mut limited_budget, &cancellation),
                        )
                        .unwrap();
                    assert!(
                        matches!(
                            limited,
                            SemanticOutcome::ExceededBudget {
                                partial: Some(_),
                                ..
                            }
                        ),
                        "{limited:?}"
                    );
                    let retained = limited.available_value().unwrap();
                    assert_eq!(retained.candidates().len(), 2);
                    assert!(
                        retained
                            .family()
                            .and_then(|family| family.membership())
                            .is_none()
                    );
                    // Exercise existing query-local transfer cache ownership.
                    let provider = WorkspaceIcfgProvider::new(&workspace);
                    let mut cold_budget = SemanticBudget::default();
                    let (cold, cold_reads) = capture_query_reads(workspace.analyzer(), || {
                        provider
                            .call_transfers(
                                call.procedure(),
                                call.id(),
                                &mut SemanticRequest::new(&mut cold_budget, &cancellation),
                            )
                            .unwrap()
                    });
                    let mut warm_budget = SemanticBudget::default();
                    let (warm, warm_reads) = capture_query_reads(workspace.analyzer(), || {
                        provider
                            .call_transfers(
                                call.procedure(),
                                call.id(),
                                &mut SemanticRequest::new(&mut warm_budget, &cancellation),
                            )
                            .unwrap()
                    });
                    assert_eq!(cold.available_value(), warm.available_value());
                    let set = warm.available_value().unwrap();
                    let inputs = set
                        .family_inputs
                        .as_ref()
                        .expect("independent transfer inputs");
                    assert_eq!(inputs.call(), &call);
                    assert_eq!(inputs.members().len(), runtime_count);
                    assert!(inputs.applies_to(&call, set), "{inputs:?}; {set:?}");
                    for member in inputs.members() {
                        assert_eq!(member.projection(), CallTransferFamilyProjection::Projected);
                        assert!(member.arity().unwrap().accepts_actuals());
                        assert_eq!(member.conversion(), CallTransferInputStatus::Satisfied);
                        assert_eq!(
                            member.capture_transport(),
                            CallTransferInputStatus::Satisfied
                        );
                        assert_eq!(
                            member.caller_evaluation(),
                            CallTransferInputStatus::Satisfied
                        );
                    }
                    for transfer in &set.transfers {
                        let raw = result
                            .candidates()
                            .iter()
                            .find(|candidate| candidate.target() == &transfer.callee)
                            .unwrap();
                        assert_eq!(&transfer.proof, raw.proof());
                        assert_eq!(&transfer.completeness, raw.completeness());
                    }
                    // The producer/projection boundary must retain independent
                    // failures even when runtime selection is already Partial.
                    // Perturb typed call/gap rows, not Java resolution rules.
                    use brokk_bifrost_analysis::analyzer::semantic::{
                        ArgumentDomain, SemanticCallArgument, SemanticCapability, SemanticGap,
                        SemanticGapDischarge, SemanticGapId, SemanticGapImpacts, SemanticGapKind,
                        SemanticGapSubject,
                        icfg::{
                            apply_call_evaluation_gaps, call_binding_arity,
                            call_binding_completeness,
                        },
                    };
                    let semantic_call = call.procedure().semantics().call_site(call.id()).unwrap();
                    let mut wrong_arity = semantic_call.clone();
                    wrong_arity.arguments = vec![SemanticCallArgument::direct(
                        semantic_call.callee,
                        ArgumentDomain::Positional,
                    )]
                    .into_boxed_slice();
                    let arity = call_binding_arity(
                        &wrong_arity,
                        set.transfers[0].callee.semantics().values(),
                    );
                    assert_eq!(arity.actuals(), 1);
                    assert_eq!(arity.fixed_formals(), 0);
                    assert!(!arity.accepts_actuals());
                    let partial = set.transfers[0].completeness.clone();
                    assert!(matches!(partial, EvidenceCompleteness::Partial(_)));
                    let (binding_gap, _) = call_binding_completeness(arity, partial.clone());
                    assert_ne!(binding_gap, partial);
                    let EvidenceCompleteness::Partial(original) = &partial else {
                        unreachable!()
                    };
                    let EvidenceCompleteness::Partial(with_arity) = &binding_gap else {
                        unreachable!()
                    };
                    assert!(with_arity.starts_with(original.as_ref()));
                    let gap = SemanticGap {
                        id: SemanticGapId::new(0),
                        point: semantic_call.point,
                        subject: SemanticGapSubject::CallSite(call.id()),
                        capability: SemanticCapability::NormalCallContinuation,
                        impacts: SemanticGapImpacts::CALL_EVALUATION,
                        kind: SemanticGapKind::Unsupported,
                        budget: None,
                        discharge: SemanticGapDischarge::None,
                        dispatch: Default::default(),
                        detail: "boundary control: caller continuation is unavailable".into(),
                        source: semantic_call.source,
                        evidence: semantic_call.evidence,
                    };
                    assert!(brokk_bifrost_analysis::analyzer::semantic::icfg::call_evaluation_gap_applies(&gap, semantic_call));
                    let mut with_gap = set.clone();
                    apply_call_evaluation_gaps(&[&gap], &mut with_gap);
                    for member in with_gap.family_inputs.as_ref().unwrap().members() {
                        assert!(member.arity().unwrap().accepts_actuals());
                        assert_eq!(member.conversion(), CallTransferInputStatus::Satisfied);
                        assert_eq!(
                            member.capture_transport(),
                            CallTransferInputStatus::Satisfied
                        );
                        assert_eq!(
                            member.caller_evaluation(),
                            CallTransferInputStatus::Unavailable
                        );
                    }
                    assert_eq!(with_gap.transfers[0].proof, set.transfers[0].proof);
                    let EvidenceCompleteness::Partial(with_caller_gap) =
                        &with_gap.transfers[0].completeness
                    else {
                        unreachable!()
                    };
                    assert!(with_caller_gap.starts_with(original.as_ref()));
                    // A carrier borrowed from the original projection must
                    // not accept changed caller evidence for the same arms.
                    assert!(!inputs.applies_to(&call, &with_gap));
                    let mut with_conversion = set.clone();
                    with_conversion.caller_conversion_may_run_user_code = true;
                    assert_eq!(with_conversion.transfers, set.transfers);
                    assert!(!inputs.applies_to(&call, &with_conversion));
                    let mut subset = set.clone();
                    subset.transfers = set.transfers[..1].to_vec().into_boxed_slice();
                    assert!(!inputs.applies_to(&call, &subset));
                    let mut duplicated = set.clone();
                    let mut rows = duplicated.transfers.into_vec();
                    rows.push(set.transfers[0].clone());
                    duplicated.transfers = rows.into_boxed_slice();
                    assert!(!inputs.applies_to(&call, &duplicated));
                    let other_call = call
                        .procedure()
                        .semantics()
                        .call_sites()
                        .iter()
                        .find(|site| site.id != call.id())
                        .unwrap();
                    let other_call = call.procedure().call_site_handle(other_call.id).unwrap();
                    assert!(!inputs.applies_to(&other_call, set));
                    let mut census = brokk_bifrost_analysis::analyzer::semantic::service::ArtifactRetentionCensus::default();
                    inputs.retained_artifacts(&mut census);
                    assert!(census.retained_bytes() > inputs.retained_bytes() as u64);
                    let mut limits = SemanticBudget::default().limits();
                    limits.owned_text_bytes = cold_budget.resident().owned_text_bytes - 1;
                    let mut metadata_limited = SemanticBudget::new(limits).unwrap();
                    let without_metadata = WorkspaceIcfgProvider::new(&workspace)
                        .call_transfers(
                            call.procedure(),
                            call.id(),
                            &mut SemanticRequest::new(&mut metadata_limited, &cancellation),
                        )
                        .unwrap();
                    let raw_only = without_metadata
                        .available_value()
                        .expect("optional metadata cannot discard paid may-targets");
                    assert_eq!(raw_only.transfers, set.transfers);
                    assert!(raw_only.family_inputs.is_none(), "{without_metadata:?}");
                    assert_eq!(metadata_limited.refusal_count(), 0);
                    assert!(
                        warm.available_value()
                            .unwrap()
                            .family
                            .as_ref()
                            .unwrap()
                            .membership()
                            .is_some()
                    );
                    let mut cold_keys = cold_reads.unordered_keys();
                    let mut warm_keys = warm_reads.unordered_keys();
                    cold_keys.sort();
                    warm_keys.sort();
                    assert_eq!(cold_keys, warm_keys);
                    assert!(
                        warm.available_value()
                            .unwrap()
                            .transfers
                            .iter()
                            .all(|transfer| matches!(transfer.proof, ProofStatus::Unproven(_)))
                    );
                    let mut values = OracleLimits::default().values();
                    values.dispatch_targets = 1;
                    let capped = WorkspaceSemanticOracle::with_limits_and_expansion(
                        &workspace,
                        OracleLimits::new(values).unwrap(),
                        expansion,
                    )
                    .resolve_call(
                        &call,
                        &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                    )
                    .unwrap();
                    let retained = capped
                        .available_value()
                        .expect("cap keeps known may-target");
                    assert_eq!(retained.candidates().len(), 1, "{capped:?}");
                    assert!(retained.family().unwrap().membership().is_none());
                    // Vary the deterministic stop point across the real
                    // pipeline, including after a known positive and between
                    // raw projection and witness publication.
                    let mut retained_positive = false;
                    let mut reached_complete = false;
                    for checks in 1..=512 {
                        let stop = CancellationToken::cancel_after_checks_for_test(checks);
                        let stopped = oracle
                            .resolve_call(
                                &call,
                                &mut SemanticRequest::new(&mut SemanticBudget::default(), &stop),
                            )
                            .unwrap();
                        if let SemanticOutcome::Cancelled {
                            partial: Some(value),
                            ..
                        } = &stopped
                        {
                            retained_positive |= !value.candidates().is_empty();
                            assert!(
                                value
                                    .family()
                                    .and_then(|family| family.membership())
                                    .is_none(),
                                "cancelled family cannot seal at stop {checks}"
                            );
                        } else if stopped
                            .available_value()
                            .and_then(|value| value.family())
                            .and_then(|family| family.membership())
                            .is_some()
                        {
                            reached_complete = true;
                            break;
                        }
                    }
                    assert!(
                        retained_positive && reached_complete,
                        "cancellation control must cross a retained positive and a completed family"
                    );
                    let cancelled = CancellationToken::default();
                    cancelled.cancel();
                    assert!(matches!(
                        oracle
                            .resolve_call(
                                &call,
                                &mut SemanticRequest::new(
                                    &mut SemanticBudget::default(),
                                    &cancelled
                                )
                            )
                            .unwrap(),
                        SemanticOutcome::Cancelled { .. }
                    ));
                }
            } else if !expansion.concrete_overrides && base.starts_with("class Base") {
                assert_eq!(
                    family.inputs().len(),
                    1,
                    "#2277 must not materialize hidden overrides"
                );
            }
        }
    }

    #[test]
    fn java_dispatch_family_membership_absence_read_and_equal_output_refresh() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::read_verification::{
            ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            verify_read_set,
        };
        use brokk_bifrost_analysis::analyzer::semantic::{
            StableDigest, workspace_oracle::one_call_dispatch_answer_digest,
        };
        use brokk_bifrost_analysis::analyzer::workspace_authority::workspace_memo_attribution;
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        let project = InlineTestProject::with_language(Language::Java)
            .file("Base.java", "interface Base { void close(); }")
            .file(
                "A.java",
                "class A implements Base { public void close() {} }",
            )
            .file(
                "Caller.java",
                "class Caller { void call(Base value) { value.close(); } }",
            )
            .build();
        let zero = StableDigest::sha256(b"unused-in-scope-verification");
        let inputs = HeadInputs {
            models: zero,
            policy_semantic_hash: zero,
            policy_source: zero,
            configuration: zero,
            epoch: zero,
        };
        let resolve = |workspace: &brokk_bifrost_analysis::WorkspaceAnalyzer| {
            let call = family_call(workspace);
            let outcome = workspace
                .semantic_oracle_provider()
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(
                        &mut SemanticBudget::default(),
                        &CancellationToken::default(),
                    ),
                )
                .unwrap();
            let family = outcome.available_value().unwrap().family().unwrap();
            let membership = family.membership().expect("complete workspace family");
            let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                membership.replay(&workspace_memo_attribution(workspace))
            });
            let keys = reads
                .unordered_keys()
                .into_iter()
                .filter(|key| matches!(key, ReadKey::Scope { .. }))
                .collect::<Vec<_>>();
            assert!(
                !keys.is_empty(),
                "membership includes complete-set/absence reads: {reads:?}"
            );
            (
                one_call_dispatch_answer_digest(&call, &outcome),
                membership.members().to_vec(),
                keys,
                family.clone(),
            )
        };
        let base = project.certified_workspace_analyzer(Default::default());
        let (base_digest, base_members, base_keys, base_family) = resolve(&base);
        assert!(
            verify_read_set(
                &base,
                &ChangedFacts::between(&base, &base),
                &inputs,
                &base_keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::default()
            )
            .is_unchanged()
        );
        // Equal semantic output must still replace its independent input receipt.
        project
            .file("Unrelated.java")
            .write("class Unrelated {}\n")
            .unwrap();
        let equal = project.certified_workspace_analyzer(Default::default());
        let (equal_digest, equal_members, equal_keys, equal_family) = resolve(&equal);
        assert_eq!(base_digest, equal_digest);
        assert_eq!(
            base_family, equal_family,
            "semantic equality excludes refreshed input receipts"
        );
        assert_eq!(base_members, equal_members);
        assert_ne!(base_keys, equal_keys);
        assert!(
            !verify_read_set(
                &equal,
                &ChangedFacts::between(&base, &equal),
                &inputs,
                &base_keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::default()
            )
            .is_unchanged()
        );
        assert!(
            verify_read_set(
                &equal,
                &ChangedFacts::between(&equal, &equal),
                &inputs,
                &equal_keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::default()
            )
            .is_unchanged()
        );
        // Root and every old member keep their bytes. Only a new override moves
        // the complete-set premise and the published membership answer.
        project
            .file("B.java")
            .write("class B implements Base { public void close() {} }\n")
            .unwrap();
        let added = project.certified_workspace_analyzer(Default::default());
        let (added_digest, added_members, _, _) = resolve(&added);
        assert_ne!(base_digest, added_digest);
        assert_eq!(added_members.len(), base_members.len() + 1);
        assert!(
            base_members
                .iter()
                .all(|member| added_members.contains(member))
        );
        let verdict = verify_read_set(
            &added,
            &ChangedFacts::between(&equal, &added),
            &inputs,
            &equal_keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::default(),
        );
        assert!(
            !verdict.is_unchanged(),
            "the old membership receipt must reject an added override"
        );
        assert!(matches!(
            verdict.changed().unwrap().key,
            ReadKey::Scope { .. }
        ));
    }
    #[test]
    fn java_dispatch_family_membership_keeps_unclosed_external_remainder() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::semantic::DispatchFamilyExternalSummaryInput;
        use brokk_bifrost_analysis::analyzer::workspace_authority::workspace_memo_attribution;
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, DispatchHierarchyExpansion, JvmAnalyzerConfig, JvmExternalArtifact,
            JvmExternalDependencies,
        };
        use brokk_bifrost_jvm_analysis::analyzer::jvm::external::{
            TestClassFile, TestClassMethod, write_test_class_jar,
        };
        let artifacts = tempfile::tempdir().unwrap();
        let jar = artifacts.path().join("family.jar");
        write_test_class_jar(
            &jar,
            &[
                TestClassFile {
                    internal_name: "ext/Base",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "close",
                        descriptor: "()V",
                        is_static: false,
                    }],
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "ext/Parent",
                    super_internal_name: "ext/Base",
                    methods: &[],
                    private_nested: false,
                },
            ],
        );
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "Caller.java",
                "import ext.Base; class Caller { void call(Base value) { value.close(); } }",
            )
            .file(
                "A.java",
                "class A extends ext.Parent { public void close() {} }",
            )
            .build();
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    artifact_paths: vec![JvmExternalArtifact {
                        artifact_path: jar,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let workspace = project.certified_workspace_analyzer(config.clone());
        let call = family_call(&workspace);
        let oracle = WorkspaceSemanticOracle::with_limits_and_expansion(
            &workspace,
            OracleLimits::default(),
            DispatchHierarchyExpansion::CONCRETE_OVERRIDES,
        );
        let outcome = oracle
            .resolve_call(
                &call,
                &mut SemanticRequest::new(
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                ),
            )
            .unwrap();
        let dispatch = outcome.available_value().unwrap();
        assert_eq!(dispatch.candidates().len(), 1, "{outcome:?}");
        let family = dispatch.family().unwrap();
        let membership = family
            .membership()
            .expect("exact artifact family is enumerated independently of missing summaries");
        assert_eq!(membership.members().len(), 1, "{family:?}");
        let remainder = membership
            .external_remainder()
            .expect("known external remainder never disappears");
        assert_eq!(
            remainder.summary_input(),
            DispatchFamilyExternalSummaryInput::Absent
        );
        assert!(remainder.bindings().is_empty());
        assert!(
            dispatch
                .boundaries()
                .iter()
                .filter_map(|boundary| boundary.unmaterialized_external_target())
                .any(|target| target.has_resolver_owned_call_shape()
                    && target.locator() == remainder.locator()
                    && target.arity() == remainder.arity()
                    && target.has_receiver() == remainder.has_receiver()
                    && target.selected_external_descriptor.as_ref() == remainder.descriptor())
        );
        assert_eq!(dispatch.coverage(), CandidateCoverage::Open);
        assert!(
            dispatch
                .candidates()
                .iter()
                .all(|candidate| matches!(candidate.proof(), ProofStatus::Unproven(_)))
        );
        assert!(dispatch.boundaries().iter().any(|boundary| {
            boundary.unmaterialized_external_target().is_some()
                && matches!(boundary.completeness, EvidenceCompleteness::Partial(_))
        }));
        let (_, reads) = capture_query_reads(workspace.analyzer(), || {
            membership.replay(&workspace_memo_attribution(&workspace))
        });
        assert!(
            reads
                .unordered_keys()
                .iter()
                .any(|key| matches!(key, ReadKey::Models(_))),
            "negative model lookup is part of the premise receipt"
        );
        assert!(
            reads
                .unordered_keys()
                .iter()
                .any(|key| matches!(key, ReadKey::Scope { .. })),
            "workspace absence is independent of the external artifact input"
        );
        project
            .file("Broken.java")
            .write("class Broken extends Missing { public void close() {} }\n")
            .unwrap();
        let open_workspace = project.certified_workspace_analyzer(config);
        let open_call = family_call(&open_workspace);
        let open = WorkspaceSemanticOracle::with_limits_and_expansion(
            &open_workspace,
            OracleLimits::default(),
            DispatchHierarchyExpansion::CONCRETE_OVERRIDES,
        )
        .resolve_call(
            &open_call,
            &mut SemanticRequest::new(
                &mut SemanticBudget::default(),
                &CancellationToken::default(),
            ),
        )
        .unwrap();
        let raw = open
            .available_value()
            .expect("an unresolved external path preserves the established workspace arm");
        assert!(
            raw.candidates().iter().any(|candidate| candidate
                .target()
                .artifact()
                .key()
                .path()
                .as_str()
                == "A.java")
        );
        assert!(raw.family().unwrap().membership().is_none());
        assert!(
            raw.boundaries()
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::HierarchyUnenumerated)
        );
    }
    #[test]
    fn java_dispatch_family_membership_requires_owned_lookup() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::config::DispatchHierarchyExpansion;
        let project = InlineTestProject::with_language(Language::Java)
            .file("Base.java", "class Base { public void close() {} }")
            .file(
                "Child.java",
                "class Child extends Base { public void close() {} }",
            )
            .file("Decoy.java", "class Decoy { public void close() {} }")
            .file(
                "Caller.java",
                "class Caller { void call(Base value) { value.close(); } }",
            )
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let call = family_call(&workspace);
        let oracle = WorkspaceSemanticOracle::with_limits_and_expansion(
            &workspace,
            OracleLimits::default(),
            DispatchHierarchyExpansion::CONCRETE_OVERRIDES,
        );
        let owned = oracle
            .resolve_call(
                &call,
                &mut SemanticRequest::new(
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                ),
            )
            .unwrap();
        let family = owned
            .available_value()
            .unwrap()
            .family()
            .unwrap()
            .membership()
            .expect("an actual source lookup can certify complete enumeration");
        assert_eq!(family.call(), &call);
        assert_eq!(family.members().len(), 2);
        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
            dispatch::exact_call_range,
            one_call_dispatch_answer_digest,
            source::{
                SourceOutcomeQuality, procedure_dispatch_answer_digest,
                procedure_dispatch_boundary_digest, procedure_dispatch_candidate_digest,
            },
        };
        let observed = oracle
            .dispatch_at_source(
                &project.file("Caller.java"),
                exact_call_range(&call).unwrap(),
                &mut SemanticRequest::new(
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                ),
            )
            .unwrap();
        assert_eq!(
            one_call_dispatch_answer_digest(&call, &owned),
            procedure_dispatch_answer_digest(
                SourceOutcomeQuality::from_outcome(&observed),
                observed.available_value()
            ),
            "source observation and one-call recording publish the same membership premises"
        );
        for (name, retained_path) in [("Base.close", "Base.java"), ("Decoy.close", "Decoy.java")] {
            let definitions = workspace.analyzer().get_definitions(name);
            let [definition] = definitions.as_slice() else {
                panic!("one selected fixture declaration: {definitions:?}");
            };
            let supplied = oracle
                .resolve_prepared_call(
                    &call,
                    PreparedCallDispatch {
                        lookup: CallDispatchLookup {
                            status: Some(DefinitionLookupStatus::Resolved),
                            targets: vec![CallDispatchTarget {
                                definition: definition.clone(),
                                proof: UsageProof::Proven,
                                native_incomplete_source_reason: None,
                            }],
                            call_application: CallApplicationKind::BoundReceiver,
                            ..CallDispatchLookup::default()
                        },
                    },
                    &mut SemanticRequest::new(
                        &mut SemanticBudget::default(),
                        &CancellationToken::default(),
                    ),
                )
                .unwrap();
            let raw = supplied.available_value().unwrap();
            assert!(
                raw.family().is_none(),
                "a caller-supplied or replaced lookup is never membership authority"
            );
            assert!(
                raw.candidates().iter().any(|candidate| candidate
                    .target()
                    .artifact()
                    .key()
                    .path()
                    .as_str()
                    == retained_path),
                "the supplied lookup keeps its existing raw projection"
            );
            if name == "Base.close" {
                let owned_dispatch = owned.available_value().unwrap();
                assert_eq!(
                    owned_dispatch
                        .candidates()
                        .iter()
                        .map(procedure_dispatch_candidate_digest)
                        .collect::<Vec<_>>(),
                    raw.candidates()
                        .iter()
                        .map(procedure_dispatch_candidate_digest)
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    owned_dispatch
                        .boundaries()
                        .iter()
                        .map(procedure_dispatch_boundary_digest)
                        .collect::<Vec<_>>(),
                    raw.boundaries()
                        .iter()
                        .map(procedure_dispatch_boundary_digest)
                        .collect::<Vec<_>>()
                );
                assert_ne!(
                    one_call_dispatch_answer_digest(&call, &owned),
                    one_call_dispatch_answer_digest(&call, &supplied),
                    "removing membership authority alone changes the recorded recipient answer"
                );
            }
        }
    }
}
