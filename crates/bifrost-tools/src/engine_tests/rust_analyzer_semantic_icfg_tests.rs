#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;

    use brokk_bifrost_analysis::analyzer::semantic::OracleRelationSubject;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::deferred_boundary_provenance;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::project_call_boundary;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ControlContinuation;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapImpact;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapSubject;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::OracleRelationKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::OracleRelationOwner;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::semantic_locator_work;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::*;

    use crate::analyzer::semantic::SemanticBudget;
    use brokk_bifrost_semantic::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    #[test]
    fn procedure_deferred_scheduling_does_not_weaken_a_nested_call_transfer() {
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::Rust,
            &[(
                "lib.rs",
                "pub fn leaf() -> i32 { 7 }\npub async fn scheduled() -> i32 { leaf() }\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Rust semantic materialization")
            .available_value()
            .cloned()
            .expect("Rust semantic artifact");
        let scheduled = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("scheduled")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("scheduled procedure");
        let scheduling_gap = scheduled
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::DeferredExecution
            })
            .expect("async procedure scheduling gap");
        assert!(
            !scheduling_gap
                .impacts
                .contains(SemanticGapImpact::CallEvaluation),
            "procedure scheduling must not claim that every represented nested call is incomplete"
        );
        let call = scheduled
            .semantics()
            .call_sites()
            .first()
            .expect("nested leaf call");
        let mut transfer_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .call_transfers(
                &scheduled,
                call.id,
                &mut SemanticRequest::new(&mut transfer_budget, &cancellation),
            )
            .expect("nested leaf call transfer");
        assert!(
            !matches!(
                &outcome,
                SemanticOutcome::Unsupported {
                    capability: SemanticCapability::DeferredExecution,
                    ..
                }
            ),
            "procedure scheduling uncertainty must not downgrade the nested call: {outcome:#?}"
        );
        let transfers = outcome
            .available_value()
            .expect("nested call transfer payload");
        assert_eq!(transfers.transfers.len(), 1, "{transfers:#?}");
        assert!(transfers.transfers.iter().all(|transfer| {
            !matches!(
                &transfer.completeness,
                EvidenceCompleteness::Partial(reason)
                    if reason.contains("caller-side call evaluation")
            )
        }));
    }

    #[test]
    #[ignore = "finds real bug: native Rust receiver typing produces no call transfer for a deferred call, so the transfer count is 0 where 1 is expected, owned by lane Y R3.4 receiver typing"]
    fn deferred_call_transfer_reprojects_provenance_and_charges_payload_atomically() {
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::Rust,
            &[
                ("leaf.rs", "pub async fn async_leaf() -> i32 { 7 }\n"),
                (
                    "lib.rs",
                    "mod leaf;\nuse crate::leaf::async_leaf;\npub fn make_future() { let _pending = async_leaf(); }\n",
                ),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Rust caller materialization")
            .available_value()
            .cloned()
            .expect("Rust caller artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("make_future")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("make_future procedure");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("async_leaf call site");
        let dispatch_provider = fixture.analyzer.icfg_provider();
        let mut dispatch_budget = SemanticBudget::default();
        let dispatch_outcome = dispatch_provider
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("Rust async dispatch");
        assert_eq!(
            dispatch_outcome
                .available_value()
                .unwrap()
                .candidates()
                .len(),
            1
        );

        // Keep the transfer's cache temperature independent from the direct
        // dispatch calibration so its exact work remains comparable to the
        // cold one-below atomic-charge probe below.
        let provider = fixture.analyzer.icfg_provider();
        let mut transfer_budget = SemanticBudget::default();
        let transfer_outcome = provider
            .call_transfers(
                &caller,
                call.id(),
                &mut SemanticRequest::new(&mut transfer_budget, &cancellation),
            )
            .expect("Rust async call transfer");
        let transfers = transfer_outcome
            .available_value()
            .expect("deferred transfer payload");
        let deferred = transfers
            .boundaries
            .iter()
            .find(|boundary| {
                matches!(
                    boundary.dispatch.kind,
                    DispatchBoundaryKind::Deferred { .. }
                )
            })
            .expect("deferred call boundary");
        assert_eq!(deferred.dispatch.provenance.len(), 1);
        assert_eq!(
            deferred.dispatch.provenance[0].owner(),
            &OracleRelationOwner::Dispatch(call.clone())
        );
        assert_eq!(
            deferred.dispatch.provenance[0].record().kind(),
            OracleRelationKind::DispatchBoundary
        );
        assert!(matches!(
            deferred.dispatch.provenance[0].record().subject(),
            Some(OracleRelationSubject::DispatchBoundary(subject))
                if subject == &deferred.dispatch.kind
        ));
        assert!(
            !deferred.dispatch.provenance[0]
                .record()
                .evidence()
                .is_empty()
        );
        let candidate = &dispatch_outcome.available_value().unwrap().candidates()[0];
        let (projected, projected_work) = deferred_boundary_provenance(
            &call,
            &deferred.dispatch.kind,
            &candidate.provenance,
            OracleLimits::default(),
        )
        .expect("direct deferred provenance projection");
        let DispatchBoundaryKind::Deferred { target, .. } = &deferred.dispatch.kind else {
            unreachable!("selected boundary is deferred")
        };
        let locator_work = semantic_locator_work(target);
        assert_eq!(
            projected_work.owned_text_bytes,
            locator_work.owned_text_bytes
        );
        assert_eq!(
            projected_work.nested_entries,
            2 + projected[0].record().evidence().len() + locator_work.nested_entries
        );
        // Dispatch may materialize a cold target while call transfer reuses
        // that semantic artifact, so their total work is not directly
        // additive. The transfer must still retain at least the independently
        // measured deferred-boundary projection; the exact one-below budget
        // assertion below proves the complete payload is charged atomically.
        assert!(
            transfer_outcome.work().nested_entries >= projected_work.nested_entries,
            "deferred transfer must retain its projected nested rows"
        );
        assert!(
            transfer_outcome.work().owned_text_bytes >= projected_work.owned_text_bytes,
            "deferred transfer must retain its projected locator text"
        );
        assert_eq!(transfer_budget.used(), transfer_outcome.work());
        let semantic_call = caller
            .semantics()
            .call_site(call.id())
            .expect("deferred semantic call");
        let continuation_projection = project_call_boundary(&caller, semantic_call, deferred)
            .expect("modeled deferred continuations");
        let expected_projection_rows = [
            semantic_call.normal_continuation,
            semantic_call.exceptional_continuation,
        ]
        .into_iter()
        .filter(|continuation| !matches!(*continuation, ControlContinuation::Absent))
        .count();
        assert_eq!(
            continuation_projection
                .edges
                .len()
                .saturating_add(continuation_projection.boundaries.len()),
            expected_projection_rows
        );
        assert!(
            continuation_projection
                .edges
                .iter()
                .all(|edge| edge.origin.as_ref() == Some(&call)
                    && edge.proof == deferred.dispatch.proof
                    && edge.completeness == deferred.dispatch.completeness)
        );

        let mut limited = SemanticBudget::default().limits();
        limited.nested_entries = transfer_outcome.work().nested_entries.saturating_sub(1);
        let mut limited_budget =
            SemanticBudget::new(limited).expect("positive deferred projection budget");
        // Measure the cold atomic charge rather than replaying the completed
        // transfer from this query-local provider's memo.
        let limited_provider = fixture.analyzer.icfg_provider();
        let limited_outcome = limited_provider
            .call_transfers(
                &caller,
                call.id(),
                &mut SemanticRequest::new(&mut limited_budget, &cancellation),
            )
            .expect("limited Rust async call transfer");
        assert!(matches!(
            limited_outcome,
            SemanticOutcome::ExceededBudget {
                partial: None,
                work,
                ..
            } if work == transfer_outcome.work()
        ));
        assert_eq!(limited_budget.used(), SemanticWork::default());
    }
}
