#[cfg(test)]
mod rust_departing_wave2_root_tests {
    use crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::*;

    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use std::path::Path;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    #[test]
    fn selected_rust_forward_cancellation_after_a_staged_answer_suppresses_prefix() {
        let fixture = RustRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let (context, crate_keys) = rust_crate_resolution_context(&operation, &cancellation);
        let locator = rust_reference_locator(&fixture.consumer_facts, "alias");
        let session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let outcome = operation
            .with_rust_forward_queries_in_session(
                context,
                &crate_keys,
                &[Path::new(RUST_ROOT_CONSUMER_PATH)],
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &session,
                |queries| {
                    let mut metrics = ResolutionBatchMetrics::default();
                    let answer = queries.resolve_reference(&locator, &mut metrics)?;
                    assert!(matches!(
                        answer,
                        SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Found(_)
                        )
                    ));
                    cancellation.cancel();
                    Ok(true)
                },
            )
            .expect("cancelled selected Rust forward operation");
        assert!(matches!(
            outcome,
            SelectedResolutionOperationOutcome::Cancelled(_)
        ));
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
    }

    #[test]
    fn selected_rust_forward_inventory_completion_certifies_an_admitted_fragment() {
        let fixture = RustRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let (context, crate_keys) = rust_crate_resolution_context(&operation, &cancellation);
        let fragment = operation
            .mounts()
            .unwrap()
            .iter()
            .find(|mount| mount.persisted_relative_path() == RUST_ROOT_CONSUMER_PATH)
            .expect("selected Rust consumer mount")
            .fragment();
        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let outcome = operation
            .with_rust_forward_queries_in_session(
                context,
                &crate_keys,
                &[Path::new(RUST_ROOT_CONSUMER_PATH)],
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &session,
                |queries| {
                    assert_eq!(
                        queries.reference_inventory_completion(fragment)?,
                        ResolutionCompletion::Complete
                    );
                    Ok(())
                },
            )
            .expect("read selected Rust reference inventory completion");
        assert!(matches!(
            outcome,
            SelectedResolutionOperationOutcome::Native(())
        ));
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Complete { .. }
        ));
    }

    #[test]
    fn selected_rust_forward_zero_scope_budget_cannot_publish_prefix() {
        let fixture = RustRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let (context, crate_keys) = rust_crate_resolution_context(&operation, &cancellation);
        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&cancellation),
        );
        let mut callback_called = false;
        let outcome = operation
            .with_rust_forward_queries_in_session(
                context,
                &crate_keys,
                &[Path::new(RUST_ROOT_CONSUMER_PATH)],
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &session,
                |_queries| {
                    callback_called = true;
                    Ok(true)
                },
            )
            .expect("zero-scope selected Rust forward operation");
        assert!(
            !callback_called,
            "zero scope must stop before callback staging"
        );
        assert!(matches!(
            outcome,
            SelectedResolutionOperationOutcome::Cancelled(_)
        ));
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
    }

    #[test]
    fn selected_rust_forward_callback_cannot_publish_after_stopped_query() {
        let fixture = RustRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let (context, crate_keys) = rust_crate_resolution_context(&operation, &cancellation);
        let locator = rust_reference_locator(&fixture.consumer_facts, "alias");
        let session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let outcome = operation
            .with_rust_forward_queries_in_session(
                context,
                &crate_keys,
                &[Path::new(RUST_ROOT_CONSUMER_PATH)],
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &session,
                |queries| {
                    let mut metrics = ResolutionBatchMetrics::default();
                    let first = queries.resolve_reference(&locator, &mut metrics)?;
                    assert!(matches!(
                        &first,
                        SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Found(_)
                        )
                    ));
                    cancellation.cancel();
                    let stopped = queries
                        .resolve_reference(&locator, &mut ResolutionBatchMetrics::default())?;
                    assert!(matches!(
                        stopped,
                        SelectedResolutionOperationOutcome::Cancelled(_)
                    ));
                    // Deliberately ignore the stopped outcome and return the first
                    // row. The enclosing operation must still discard it.
                    Ok(first)
                },
            )
            .expect("stopped selected Rust forward operation");
        assert!(matches!(
            outcome,
            SelectedResolutionOperationOutcome::Cancelled(_)
        ));
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
    }
}
