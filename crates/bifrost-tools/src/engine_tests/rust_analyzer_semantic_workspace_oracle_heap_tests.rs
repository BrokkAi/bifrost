#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::analyzer::semantic::HeapOracle;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValueKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::heap::PointsToResult;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::AbstractObjectIdentity;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DurableCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::ObservationPhase;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::ValueAtPoint;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::common::WorkStager;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::incoming_actual_queries;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#4929: one source judgement enumerated the same formal's callers once per observation"
    )]
    fn incoming_actual_is_rebased_to_the_callee_with_query_context() {
        let source = r#"
struct Payload(u8);

fn helper(payload: &Payload) {
    let observed = payload;
    let _byte = observed.0;
}

fn caller() {
    let payload = Payload(1);
    helper(&payload);
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Rust semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Rust semantic artifact is available");
        let helper_semantics = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.values().iter().any(|value| {
                    matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. })
                })
            })
            .expect("helper procedure with a formal parameter");
        let formal = helper_semantics
            .values()
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
            .expect("helper formal value");
        let helper = artifact
            .procedure_handle(helper_semantics.id())
            .expect("helper procedure handle");
        let caller_semantics = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("caller procedure with the helper call");
        let caller = artifact
            .procedure_handle(caller_semantics.id())
            .expect("caller procedure handle");
        let incoming_call = caller_semantics
            .call_sites()
            .first()
            .expect("caller invokes the helper");
        let incoming_call = caller
            .call_site_handle(incoming_call.id)
            .expect("helper call handle");
        let identity_context =
            OracleCallContext::bounded(vec![incoming_call], OracleLimits::default());
        let durable_context = DurableCallContext::of(&identity_context)
            .expect("query call context has a durable form");
        let query = ValueAtPoint::new(
            helper
                .value_handle(formal.id)
                .expect("helper parameter handle"),
            helper
                .point_handle(helper_semantics.entry_point())
                .expect("helper entry point"),
            ObservationPhase::BeforeEffects,
            identity_context.clone(),
        )
        .expect("formal observation");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .pointees(
                &query,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("helper formal points-to query validates");
        assert_eq!(
            oracle
                .incoming_actuals
                .actuals
                .account(|actuals| actuals.lock().expect("incoming actual memo poisoned").len()),
            1
        );
        let request = SemanticRequest::new(&mut budget, &cancellation);
        let mut hit = WorkStager::new(&request);
        incoming_actual_queries(
            &oracle,
            &helper,
            formal.id,
            &identity_context,
            *oracle.limits(),
            &mut hit,
            &cancellation,
        )
        .unwrap_or_else(|_| panic!("completed incoming query must be reusable"));
        assert_eq!(
            hit.work,
            SemanticWork::default(),
            "memo hits charge no work"
        );
        let mut reused_budget = SemanticBudget::default();
        let reused = oracle
            .pointees(
                &query,
                &mut SemanticRequest::new(&mut reused_budget, &cancellation),
            )
            .expect("memoized points-to query validates");
        // Each points-to result owns a fresh provenance arena. Compare the
        // semantic answer, not those deliberately distinct arena handles.
        let answer = |outcome: &SemanticOutcome<PointsToResult>| {
            let objects = outcome
                .available_value()
                .expect("points-to answer")
                .objects();
            (
                objects.coverage(),
                objects
                    .candidates()
                    .iter()
                    .map(|candidate| {
                        (
                            candidate
                                .value()
                                .identity()
                                .durable_identity()
                                .expect("durable object"),
                            candidate.value().cardinality(),
                            candidate.proof().clone(),
                            candidate.completeness().clone(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(answer(&reused), answer(&outcome));
        // A new provider starts with an empty incoming-actual memo.
        let fresh_oracle = fixture.analyzer.semantic_oracle_provider();
        let mut fresh_budget = SemanticBudget::default();
        let fresh = fresh_oracle
            .pointees(
                &query,
                &mut SemanticRequest::new(&mut fresh_budget, &cancellation),
            )
            .expect("unmemoized points-to query validates");
        assert_eq!(answer(&fresh), answer(&reused));
        let points_to = outcome
            .available_value()
            .expect("partial results retain the substituted candidate");
        let candidate = points_to
            .objects()
            .candidates()
            .iter()
            .find(|candidate| {
                matches!(
                    candidate.value().identity(),
                    AbstractObjectIdentity::CallSubstitution {
                        procedure,
                        context,
                        ..
                    } if procedure == &helper && context == &identity_context
                )
            })
            .expect("incoming candidate is owned by the helper and records its call context");
        assert!(matches!(
            candidate
                .value()
                .identity()
            .durable_identity()
            .expect("callee-scoped identity has a durable form"),
            crate::analyzer::semantic::DurableObjectIdentity::CallSubstitution {
                context,
                ..
            } if context == durable_context
        ));
    }
}
