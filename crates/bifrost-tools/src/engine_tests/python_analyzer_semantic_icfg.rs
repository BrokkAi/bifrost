#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::ReturnTransferKind;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::WorkspaceIcfgProvider;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::gap_affects_matched_return;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ControlEdgeKind;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapImpact;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapKind;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::type_flow::DispatchHints;
    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::*;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHintCallSiteKey;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHintSet;

    use crate::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    fn dispatch_hint_order_is_canonical_and_separates_provider_behavior() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[(
                "caller.py",
                "def caller(x):\n    x.first()\n    return x.second()\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "caller.py");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Python caller materialization")
            .available_value()
            .cloned()
            .expect("Python caller artifact");
        let procedure = artifact
            .procedures()
            .first()
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let calls = procedure.semantics().call_sites();
        assert_eq!(calls.len(), 2);
        let first = DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&procedure, calls[0].id),
            Vec::new(),
            true,
            brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHintProof::Proven,
        );
        let second = DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&procedure, calls[1].id),
            Vec::new(),
            true,
            brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHintProof::Proven,
        );
        let forward = DispatchHints::new(vec![first.clone(), second.clone()]);
        let reverse = DispatchHints::new(vec![second, first]);
        assert_eq!(forward.digest(), reverse.digest());

        let open = DispatchHints::new(vec![DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&procedure, calls[0].id),
            Vec::new(),
            false,
            brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHintProof::Unproven,
        )]);
        assert_ne!(forward.digest(), open.digest());

        let unhinted =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.analyzer, None);
        let hinted = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            None,
            forward,
        );
        assert_ne!(unhinted.behavior_identity(), hinted.behavior_identity());
        assert_ne!(
            unhinted.behavior_identity().read_digest(),
            hinted.behavior_identity().read_digest()
        );
    }
    #[test]
    #[hardwon("#1952: an unrelated return gap hid the path-relevant completion result")]
    fn python_mixed_return_gaps_retain_only_the_matched_normal_reason() {
        const SOURCE: &str = "async def target(value):\n    result = value\n    return result\n";
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            &[("mixed_return_gaps.py", SOURCE)],
        );
        let file = ProjectFile::new(fixture.project_root(), "mixed_return_gaps.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Python materialization")
            .available_value()
            .cloned()
            .expect("Python artifact");
        let target = artifact
            .procedures()
            .first()
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("target procedure");
        let semantics = target.semantics();
        // An ordinary Python operation's implicit abort is a lowered route
        // into the enclosing structured completion, not a published
        // exceptional-flow gap, so the procedure's only return-affecting gap
        // is the subject-wide async-suspension gap. The exit profile
        // discharges implicit-abort gaps when no abort path runs user code
        // (#1952); the expected reasons below apply the same rule.
        let abort_user_code =
            brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::value_flow::abort_paths_run_user_code(semantics);
        let all_gaps = semantics
            .gaps()
            .iter()
            .filter(|gap| gap.impacts.contains(SemanticGapImpact::ReturnTransfer))
            .collect::<Vec<_>>();
        assert!(
            all_gaps.iter().all(|gap| {
                !(gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.kind == SemanticGapKind::Unsupported)
            }),
            "the assignment's implicit abort must be a modeled exceptional \
             edge rather than an unsupported exceptional-flow gap: {all_gaps:#?}"
        );
        // The store lowers its implicit abort from the statement's own
        // boundary point, so the abort edge leaves the point whose source
        // mapping anchors at the whole assignment statement rather than the
        // point that carries the `Assignment` effect.
        let statement_anchor = SOURCE
            .find("result = value")
            .expect("the fixture names the assignment statement");
        let assignment_abort = semantics
            .cfg()
            .edges()
            .iter()
            .find(|edge| {
                edge.kind == ControlEdgeKind::Exceptional
                    && semantics.point(edge.source_point).is_some_and(|point| {
                        semantics
                            .source_mapping(point.source)
                            .is_some_and(|mapping| {
                                mapping.locator.anchor().span().start_byte() as usize
                                    == statement_anchor
                            })
                    })
            })
            .expect("the assignment's implicit abort is a modeled exceptional edge");
        assert_ne!(
            assignment_abort.target_point,
            semantics.exceptional_exit_point(),
            "the assignment's abort routes into the structured completion"
        );
        let return_gaps = all_gaps
            .iter()
            .copied()
            .filter(|gap| {
                !brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::value_flow::implicit_abort_gap_is_discharged(
                    gap,
                    abort_user_code,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            return_gaps.iter().any(|gap| {
                gap.capability == SemanticCapability::AsyncSuspendResume
                    && gap.kind == SemanticGapKind::Unsupported
            }),
            "async lowering must retain its suspension gap: {return_gaps:#?}"
        );
        assert_eq!(
            return_gaps.len(),
            1,
            "the async-suspension gap is the only return-affecting gap left: {return_gaps:#?}"
        );
        let aggregate_reason = return_gaps
            .iter()
            .map(|gap| {
                format!(
                    "{} {}: {}",
                    gap.kind.label(),
                    gap.capability.label(),
                    gap.detail,
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let matched_reason = return_gaps
            .iter()
            .filter(|gap| gap_affects_matched_return(gap, ReturnTransferKind::Normal))
            .map(|gap| {
                format!(
                    "{} {}: {}",
                    gap.kind.label(),
                    gap.capability.label(),
                    gap.detail,
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        assert!(!matched_reason.is_empty());
        assert!(!matched_reason.contains(SemanticCapability::ExceptionalControlFlow.label()));

        let entry = target
            .point_handle(semantics.entry_point())
            .expect("target entry");
        let exit = target
            .point_handle(semantics.normal_exit_point())
            .expect("target normal exit");
        let provider = fixture.analyzer.icfg_provider();
        let mut budget = SemanticBudget::default();
        let outcome = provider
            .exit_profile(
                &entry,
                &exit,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("target exit profile");
        let profile = outcome.available_value().expect("retained profile");
        assert_eq!(
            profile.aggregate_return_affecting_gap_reason(),
            Some(aggregate_reason.as_str())
        );
        assert_eq!(matched_reason, aggregate_reason);
        assert_eq!(
            profile.matched_return_affecting_gap_reason(),
            Some(matched_reason.as_str()),
            "the matched reason falls back to the aggregate because the two \
             gap sets now coincide"
        );
        // The profile charges the matched reason only when it names a distinct
        // gap set, which it no longer does here.
        let expected_text_bytes = aggregate_reason.len();
        assert_eq!(outcome.work().owned_text_bytes, expected_text_bytes);
        assert_eq!(budget.used(), outcome.work());

        let mut limited_work = SemanticBudget::default().limits();
        limited_work.owned_text_bytes = expected_text_bytes
            .checked_sub(1)
            .expect("mixed return-gap reasons are non-empty");
        let mut limited_budget =
            SemanticBudget::new(limited_work).expect("all semantic limits remain positive");
        // Measure the cold atomic charge rather than replaying the completed
        // profile from this query-local provider's memo.
        let limited_provider = fixture.analyzer.icfg_provider();
        let limited = limited_provider
            .exit_profile(
                &entry,
                &exit,
                &mut SemanticRequest::new(&mut limited_budget, &cancellation),
            )
            .expect("owned-text boundary is a typed semantic outcome");
        assert!(matches!(
            limited,
            SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            } if exceeded.dimension()
                == crate::analyzer::semantic::SemanticBudgetDimension::OwnedTextBytes
                && exceeded.limit() == expected_text_bytes - 1
                && exceeded.attempted() == expected_text_bytes
                && work.owned_text_bytes == 0
        ));
    }
}

#[cfg(test)]
mod python_residency_tests {
    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::*;

    use crate::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::python_test_support::assert_failed_transfer_retry_pays_source;
    #[test]
    #[hardwon("#5113: failed transfer projection erased performed source scan work")]
    fn failed_source_charge_does_not_publish_an_unpaid_icfg_dispatch_session() {
        let source = concat!(
            "async def target():\n    pass\n\n",
            "def caller():\n    target()\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::Python,
            &[("call.py", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "call.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Python semantic materialization")
            .available_value()
            .cloned()
            .expect("Python semantic artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = caller.semantics().call_sites()[0].id;
        let provider = fixture.analyzer.icfg_provider();

        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = source.len() - 1;
        let mut tight_budget = SemanticBudget::new(limits).expect("positive tight source budget");
        let failed = provider
            .call_transfers(
                &caller,
                call,
                &mut SemanticRequest::new(&mut tight_budget, &cancellation),
            )
            .expect("source-budget exhaustion is typed");
        assert!(matches!(
            failed,
            SemanticOutcome::ExceededBudget { partial: None, .. }
        ));
        assert_eq!(tight_budget.used(), SemanticWork::default());
        assert_failed_transfer_retry_pays_source(
            &provider,
            &caller,
            call,
            source.len(),
            &cancellation,
        );

        assert_eq!(
            artifact
                .procedures()
                .iter()
                .find(|p| p.properties().is_async)
                .expect("async target")
                .properties()
                .invocation,
            brokk_bifrost_semantic::analyzer::semantic::ProcedureInvocationKind::Deferred,
        );
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let mut dispatch_budget = SemanticBudget::default();
        let dispatch = oracle
            .resolve_call(
                &caller.call_site_handle(call).expect("typed call handle"),
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("dispatch calibration");
        assert!(dispatch.available_value().is_some(), "{dispatch:#?}");
        assert!(dispatch_budget.root_work_peak().source_bytes > 0);
        let mut projection_limits = SemanticBudget::default().limits();
        projection_limits.nested_entries = dispatch_budget.resident_peak().nested_entries;
        let mut projection_budget = SemanticBudget::new_child(
            projection_limits,
            &SemanticBudget::default().scope_snapshot(),
        );
        let projection_provider = fixture.analyzer.icfg_provider();
        let failed = projection_provider
            .call_transfers(
                &caller,
                call,
                &mut SemanticRequest::new(&mut projection_budget, &cancellation),
            )
            .expect("typed projection refusal");
        assert!(
            matches!(
                failed,
                SemanticOutcome::ExceededBudget { partial: None, .. }
            ),
            "{failed:#?}"
        );
        assert_eq!(projection_budget.resident(), SemanticWork::default());
        assert_eq!(
            projection_budget.root_work_peak().source_bytes,
            dispatch_budget.root_work_peak().source_bytes,
            "source scan work survives rejection of the projected transfer",
        );
        assert_failed_transfer_retry_pays_source(
            &projection_provider,
            &caller,
            call,
            source.len(),
            &cancellation,
        );
    }
}
