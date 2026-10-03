use super::*;

fn rust_reference_locator(facts: &FileResolutionFacts, spelling: &str) -> SelectedSemanticLocator {
    let site = site_for_identifier(
        facts,
        spelling,
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let range = facts
        .sites
        .iter()
        .find(|candidate| candidate.id == site)
        .expect("Rust forward reference range");
    SelectedSemanticLocator::for_reference_range(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
        range.start_byte,
        range.end_byte,
    )
}

/// The consumer file's context and the crates that compile it, which is what a
/// forward session takes: the context answers its references and the crate keys
/// are the scope it binds inside.
fn rust_crate_resolution_context(
    operation: &SelectedResolutionOperation<'_, '_>,
    cancellation: &CancellationToken,
) -> (SelectedResolutionContextSet, Vec<[u8; 32]>) {
    let SelectedRustFileContextOutcome::Ready {
        context,
        crate_keys,
    } = operation
        .rust_context_for_file(Path::new(RUST_ROOT_CONSUMER_PATH), cancellation)
        .expect("build selected Rust consumer-crate context")
    else {
        panic!("selected Rust consumer-crate context must be ready")
    };
    (*context, crate_keys)
}

#[test]
fn selected_rust_forward_session_resolves_multiple_refs_and_reuses_fact_session() {
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let (context, crate_keys) = rust_crate_resolution_context(&operation, &cancellation);
    let locators = [
        rust_reference_locator(&fixture.consumer_facts, "alias"),
        rust_reference_locator(&fixture.consumer_facts, "direct_alias"),
    ];
    let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let mut callback_count = 0;
    let outcome = operation
        .with_rust_forward_queries_in_session(
            context,
            &crate_keys,
            &[Path::new(RUST_ROOT_CONSUMER_PATH)],
            &cancellation,
            &mut SelectedResolutionContextMetrics,
            &session,
            |queries| {
                callback_count += 1;
                let mut first_metrics = ResolutionBatchMetrics::default();
                let first = queries.resolve_reference(&locators[0], &mut first_metrics)?;
                let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    first,
                )) = first
                else {
                    panic!("first selected Rust forward reference must resolve")
                };
                assert_eq!(first.resolution.binding().targets().len(), 1);
                assert_eq!(
                    first.resolution.binding().completion(),
                    &ResolutionCompletion::Complete
                );

                let mut second_metrics = ResolutionBatchMetrics::default();
                let second = queries.resolve_reference(&locators[1], &mut second_metrics)?;
                let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    second,
                )) = second
                else {
                    panic!("second selected Rust forward reference must resolve")
                };
                assert_eq!(second.resolution.binding().targets().len(), 1);
                assert_eq!(
                    second.resolution.binding().completion(),
                    &ResolutionCompletion::Complete
                );

                let mut repeat_metrics = ResolutionBatchMetrics::default();
                let repeated = queries.resolve_reference(&locators[0], &mut repeat_metrics)?;
                let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    repeated,
                )) = repeated
                else {
                    panic!("repeated selected Rust forward reference must resolve")
                };
                assert_eq!(
                    repeated.resolution.binding().targets(),
                    first.resolution.binding().targets(),
                    "repeated references must reuse the same session answer"
                );
                assert_eq!(repeat_metrics, first_metrics);
                Ok(())
            },
        )
        .expect("run selected Rust forward query session");

    assert_eq!(callback_count, 1, "all references must share one callback");
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
                    SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(_))
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
                let result =
                    queries.resolve_reference(&locator, &mut ResolutionBatchMetrics::default())?;
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
                    SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(_))
                ));
                cancellation.cancel();
                let stopped =
                    queries.resolve_reference(&locator, &mut ResolutionBatchMetrics::default())?;
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
