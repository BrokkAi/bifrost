#[cfg(test)]
mod rust_departing_root_tests {
    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

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

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::rust_root_test_support::parsed_operation_source_state as parsed_operation_source_state;

    use crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::rust_crate_resolution_context as rust_crate_resolution_context;

    use crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::rust_reference_locator as rust_reference_locator;
    #[test]
    fn selected_rust_forward_preserves_complete_binding_and_incomplete_call_aggregate() {
        let fixture = RustRootResolutionOperationFixture::new();
        // An attribute on an argument can remove it, so each call keeps its
        // call-site applicability gap: invocation uncertainty the name binding
        // must not absorb.
        let source = concat!(
            "use engine::target as alias;\n",
            "use engine::model::target as direct_alias;\n",
            "async fn caller<T: Copy>(value: T) -> usize {\n",
            "    alias(#[cfg(any())] value) + direct_alias(#[cfg(any())] value)\n",
            "}\n",
        );
        let (state, facts) = parsed_operation_source_state(
            fixture._project_root.path(),
            RUST_ROOT_CONSUMER_PATH,
            source,
            &RustAdapter,
        );
        let cancellation = CancellationToken::new();
        let replacement = fixture.publish_counterfactual_content(
            RUST_ROOT_CONSUMER_PATH,
            source,
            &state,
            &cancellation,
        );
        let masks = [SelectedResolutionOverlayMask::replacement(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
        )];
        let operation = fixture.open_content_selected(&masks, vec![replacement], &cancellation);
        let (context, crate_keys) = rust_crate_resolution_context(&operation, &cancellation);
        let locators = [
            rust_reference_locator(&facts, "alias"),
            rust_reference_locator(&facts, "direct_alias"),
        ];
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
                    for locator in &locators {
                        let mut metrics = ResolutionBatchMetrics::default();
                        let answer = queries.resolve_reference(locator, &mut metrics)?;
                        let SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Found(answer),
                        ) = answer
                        else {
                            panic!("generic async Rust call reference must resolve")
                        };
                        assert_eq!(answer.resolution.binding().targets().len(), 1);
                        assert_eq!(
                            answer.resolution.binding().completion(),
                            &ResolutionCompletion::Complete,
                            "name binding remains complete despite invocation uncertainty"
                        );
                        assert!(matches!(
                            answer.resolution.completion(),
                            ResolutionCompletion::Incomplete(_)
                        ));
                    }
                    Ok(())
                },
            )
            .expect("run selected generic async Rust forward queries");

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
    fn selected_rust_forward_unavailable_cannot_publish_callback_value() {
        let fixture = RustRootResolutionOperationFixture::new();
        let (provider_state, _) = parsed_operation_source_state(
            fixture._project_root.path(),
            RUST_ROOT_PROVIDER_PATH,
            RUST_ROOT_PROVIDER_SOURCE,
            &RustAdapter,
        );
        let cancellation = CancellationToken::new();
        let replacement = fixture.publish_counterfactual_content(
            RUST_ROOT_PROVIDER_PATH,
            RUST_ROOT_PROVIDER_SOURCE,
            &provider_state,
            &cancellation,
        );
        let masks = [SelectedResolutionOverlayMask::replacement(
            "rust",
            RUST_ROOT_PROVIDER_PATH,
        )];
        let blob_id = replacement.publication().blob_id();
        // Inject a lost parser-unit projection after complete publication. The
        // structured binding graph and source declaration remain authoritative;
        // only the user-facing CodeUnit projection becomes unavailable. Open after
        // this mutation so freshness captures it rather than returning Stale.
        fixture.store.conn.execute(move |connection| {
            assert!(connection.execute(
            "UPDATE code_units SET in_declarations=0 WHERE blob_id=?1 AND in_declarations=1",
            [blob_id],
        ).expect("remove published parser-unit projection") > 0);
        });
        let operation = fixture.open_content_selected(&masks, vec![replacement], &cancellation);
        let (context, crate_keys) = rust_crate_resolution_context(&operation, &cancellation);
        let locator = rust_reference_locator(&fixture.consumer_facts, "alias");
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
                    let result = queries
                        .resolve_reference(&locator, &mut ResolutionBatchMetrics::default())?;
                    assert!(matches!(
                        result,
                        SelectedResolutionOperationOutcome::Unavailable(_)
                    ));
                    // Deliberately ignore the unavailable result and return a
                    // callback value. The enclosing operation must suppress it.
                    Ok(true)
                },
            )
            .expect("selected Rust forward unavailable result");
        assert!(matches!(
            outcome,
            SelectedResolutionOperationOutcome::Unavailable(_)
        ));
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Complete { .. }
        ));
    }
}
