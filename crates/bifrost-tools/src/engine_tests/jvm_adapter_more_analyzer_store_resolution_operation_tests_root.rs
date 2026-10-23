#[cfg(test)]
mod jvm_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::CountRollbackStager;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::MutableGenerationProject as MutableGenerationProject;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::PROVIDER_JAVA_SOURCE;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::PROVIDER_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::REMOVED_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::RICH_JAVA_SOURCE;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::RollbackStager;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::SECOND_REPLACEMENT_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::SOURCE_PATH;

    use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextIdentities;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionFallbackReason;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationMount;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenResult;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationResult;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::WORKSPACE_ID;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::assert_semantic_summary_eq;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::assert_store_error_contains as assert_store_error_contains;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::begin_production_selected_sql_trace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::canonical_broad_rows;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::checkpoint_production_selected_sql_trace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::content_mount_request as content_mount_request;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::dispatch_usize;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::finish_production_selected_sql_trace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::mount_lookup as mount_lookup;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::open_ready_operation as open_ready_operation;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_source_state as parsed_operation_source_state;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state as parsed_operation_state;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::persist_test_workspace_snapshot as persist_test_workspace_snapshot;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::persisted_oid;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::provider_method_site;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::selected_operation_input as selected_operation_input;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::semantic_at as semantic_at;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::site_for_identifier as site_for_identifier;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    #[cfg(test)]
    use git2::ObjectType;
    #[cfg(test)]
    use git2::Oid;

    #[cfg(test)]
    use std::cell::RefCell;

    use std::path::Path;

    #[cfg(test)]
    use brokk_bifrost_core::cancellation::CancellationToken;
    #[cfg(test)]
    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
    #[cfg(test)]
    use std::rc::Rc;
    #[cfg(test)]
    use std::sync::Arc;
    #[cfg(test)]
    use std::sync::atomic::Ordering;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionContextSet;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::GenerationId;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::Result;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::StoreError;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionContentMountRequest;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionStale;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::Language;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::project::Project;

    # [cfg (test)]
 use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::rust_root_test_support::counterfactual_content_mount as counterfactual_content_mount;
    #[test]
    fn published_replacements_are_exact_sorted_dense_mounts() {
        let fixture = ResolutionOperationFixture::new();
        let masks = fixture.two_replacement_masks();
        let cancellation = CancellationToken::default();

        let first = fixture.open_ready(
            &masks,
            vec![fixture.second_replacement(), fixture.provider_replacement()],
            &cancellation,
        );
        let first_mounts = first.mounts().unwrap().to_vec();
        assert_eq!(
            first_mounts
                .iter()
                .map(|mount| {
                    (
                        mount.ordinal().get(),
                        mount.persisted_relative_path(),
                        mount.storage_language(),
                        mount.semantic_language(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (0, SOURCE_PATH, "java", Language::Java),
                (1, PROVIDER_PATH, "java", Language::Java),
                (2, SECOND_REPLACEMENT_PATH, "java", Language::Java),
            ]
        );
        assert!(
            first_mounts
                .iter()
                .all(|mount| mount.persisted_relative_path() != REMOVED_PATH),
            "a removal owns no selected ordinal"
        );
        drop(first);

        let permuted = fixture.open_ready(
            &masks,
            vec![fixture.provider_replacement(), fixture.second_replacement()],
            &cancellation,
        );
        assert_eq!(permuted.mounts().unwrap(), first_mounts.as_slice());
        drop(permuted);

        assert!(matches!(
            fixture
                .open(&masks, vec![fixture.provider_replacement()], &cancellation)
                .unwrap(),
            SelectedResolutionOperationOpenOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingTransientReplacement {
                    storage_language,
                    persisted_relative_path
                }
            ) if storage_language == "java" && persisted_relative_path == SECOND_REPLACEMENT_PATH
        ));
        assert!(matches!(
            fixture.open(
                &masks,
                vec![
                    fixture.provider_replacement(),
                    fixture.second_replacement(),
                    fixture.counterfactual_content(
                        "src/E_Extra.java",
                        RICH_JAVA_SOURCE,
                        RICH_JAVA_SOURCE,
                    ),
                ],
                &cancellation,
            ).unwrap(),
            SelectedResolutionOperationOpenOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingTransientOverlayInput {
                    storage_language,
                    persisted_relative_path,
                }
            ) if storage_language == "java" && persisted_relative_path == "src/E_Extra.java"
        ));
        assert_store_error_contains(
            fixture.open(
                &masks,
                vec![
                    fixture.provider_replacement(),
                    fixture.provider_replacement(),
                    fixture.second_replacement(),
                ],
                &cancellation,
            ),
            "duplicate selected resolution content mount",
        );
    }
    #[test]
    fn selected_operation_requires_the_live_overlay_digest_and_rejects_clear() {
        let fixture = ResolutionOperationFixture::new();
        let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
        let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
        let original = "class Provider {}\n";
        let changed = "class ProviderChanged {}\n";
        assert!(overlay.set(file.abs_path(), original.to_owned()));
        let original_digest =
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes());
        let masks = [SelectedResolutionOverlayMask::replacement(
            "java",
            PROVIDER_PATH,
        )];

        assert!(overlay.set(file.abs_path(), changed.to_owned()));
        let stale = fixture
            .open_with_project_and_content_mounts(
                &overlay,
                &masks,
                vec![fixture.live_content(PROVIDER_PATH, original)],
                &CancellationToken::default(),
            )
            .expect("stale overlay preflight must not fail the store call");
        assert!(matches!(
            stale,
            SelectedResolutionOperationOpenOutcome::Stale(
                SelectedResolutionStale::TransientOverlayChanged {
                    storage_language,
                    persisted_relative_path,
                    expected_content_digest,
                    actual_content_digest: Some(_),
                }
            ) if storage_language == "java"
                && persisted_relative_path == PROVIDER_PATH
                && expected_content_digest == original_digest
        ));

        assert!(overlay.set(file.abs_path(), original.to_owned()));
        assert!(overlay.clear(&file.abs_path()));
        let cleared = fixture
            .open_with_project_and_content_mounts(
                &overlay,
                &masks,
                vec![fixture.live_content(PROVIDER_PATH, original)],
                &CancellationToken::default(),
            )
            .expect("cleared overlay preflight must not fail the store call");
        assert!(matches!(
            cleared,
            SelectedResolutionOperationOpenOutcome::Stale(
                SelectedResolutionStale::TransientOverlayChanged {
                    storage_language,
                    persisted_relative_path,
                    expected_content_digest,
                    actual_content_digest: None,
                }
            ) if storage_language == "java"
                && persisted_relative_path == PROVIDER_PATH
                && expected_content_digest == original_digest
        ));
    }
    #[test]
    fn selected_operation_accepts_a_matching_cached_content_mount_authority() {
        let fixture = ResolutionOperationFixture::new();
        let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
        let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
        let source = "class Provider {}\n";
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
        let masks = [SelectedResolutionOverlayMask::replacement(
            "java",
            PROVIDER_PATH,
        )];
        let result = fixture
            .open_with_project_and_content_mounts(
                &overlay,
                &masks,
                vec![
                    fixture
                        .content_mount(PROVIDER_PATH)
                        .with_live_overlay_content_digest(digest),
                ],
                &CancellationToken::default(),
            )
            .expect("matching cached content authority must not fail the store call");
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = result else {
            panic!("matching cached content authority must open Ready")
        };
        let provider = operation
            .mounts()
            .unwrap()
            .iter()
            .find(|mount| mount.persisted_relative_path() == PROVIDER_PATH)
            .expect("cached provider mount");
        let selected = operation
            .ready
            .inventory
            .mount_record_by_ordinal(provider.ordinal())
            .unwrap();
        assert!(selected.file_version_id().is_none());
        assert_eq!(selected.blob_oid(), persisted_oid());
    }
    #[test]
    fn selected_operation_rejects_cached_content_authority_before_sql_when_wrong_or_cleared() {
        let fixture = ResolutionOperationFixture::new();
        let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
        let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
        let source = "class Provider {}\n";
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
        let masks = [SelectedResolutionOverlayMask::replacement(
            "java",
            PROVIDER_PATH,
        )];

        begin_production_selected_sql_trace(&fixture.store);
        let wrong = fixture
            .open_with_project_and_content_mounts(
                &overlay,
                &masks,
                vec![
                    fixture
                        .content_mount(PROVIDER_PATH)
                        .with_live_overlay_content_digest([0x5a; 32]),
                ],
                &CancellationToken::default(),
            )
            .expect("wrong cached content authority must not fail the store call");
        let wrong_cost = finish_production_selected_sql_trace(&fixture.store);
        assert_eq!(wrong_cost.statement_count(), 0);
        assert!(matches!(
            wrong,
            SelectedResolutionOperationOpenOutcome::Stale(
                SelectedResolutionStale::TransientOverlayChanged {
                    storage_language,
                    persisted_relative_path,
                    expected_content_digest,
                    actual_content_digest: Some(_),
                }
            ) if storage_language == "java"
                && persisted_relative_path == PROVIDER_PATH
                && expected_content_digest == [0x5a; 32]
        ));

        assert!(overlay.clear(&file.abs_path()));
        begin_production_selected_sql_trace(&fixture.store);
        let cleared = fixture
            .open_with_project_and_content_mounts(
                &overlay,
                &masks,
                vec![
                    fixture
                        .content_mount(PROVIDER_PATH)
                        .with_live_overlay_content_digest(digest),
                ],
                &CancellationToken::default(),
            )
            .expect("cleared cached content authority must not fail the store call");
        let cleared_cost = finish_production_selected_sql_trace(&fixture.store);
        assert_eq!(cleared_cost.statement_count(), 0);
        assert!(matches!(
            cleared,
            SelectedResolutionOperationOpenOutcome::Stale(
                SelectedResolutionStale::TransientOverlayChanged {
                    storage_language,
                    persisted_relative_path,
                    expected_content_digest,
                    actual_content_digest: None,
                }
            ) if storage_language == "java"
                && persisted_relative_path == PROVIDER_PATH
                && expected_content_digest == digest
        ));
    }
    #[test]
    fn selected_operation_rechecks_cached_content_authority_at_final_boundary() {
        let fixture = ResolutionOperationFixture::new();
        let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
        let source = "class Provider {}\n";
        let changed = "class ProviderChanged {}\n";
        fixture.project.set_overlay_content(file.clone(), source);
        let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
        let masks = [SelectedResolutionOverlayMask::replacement(
            "java",
            PROVIDER_PATH,
        )];
        let operation = match fixture
            .open_with_project_and_content_mounts(
                &fixture.project,
                &masks,
                vec![
                    fixture
                        .content_mount(PROVIDER_PATH)
                        .with_live_overlay_content_digest(digest),
                ],
                &CancellationToken::default(),
            )
            .expect("matching cached content authority must open")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("matching cached content authority must open Ready"),
        };
        let mut ready = operation.ready;
        fixture.project.set_overlay_content(file, changed);
        assert_eq!(fixture.project.analysis_generation(), 0);
        let result = ready.finish(
            (),
            &ResolutionCompletion::Complete,
            &CancellationToken::default(),
        );
        assert!(matches!(
            result.unwrap(),
            SelectedResolutionOperationOutcome::Stale(
                SelectedResolutionStale::TransientOverlayChanged {
                    storage_language,
                    persisted_relative_path,
                    expected_content_digest,
                    actual_content_digest: Some(_),
                }
            ) if storage_language == "java"
                && persisted_relative_path == PROVIDER_PATH
                && expected_content_digest == digest
        ));
    }
    #[test]
    fn selected_operation_revalidates_cached_content_publication_before_native() {
        let fixture = ResolutionOperationFixture::new();
        let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
        let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
        let source = "class Provider {}\n";
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
        let masks = [SelectedResolutionOverlayMask::replacement(
            "java",
            PROVIDER_PATH,
        )];
        let operation = match fixture
            .open_with_project_and_content_mounts(
                &overlay,
                &masks,
                vec![
                    fixture
                        .content_mount(PROVIDER_PATH)
                        .with_live_overlay_content_digest(digest),
                ],
                &CancellationToken::default(),
            )
            .expect("matching cached content authority must open")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("matching cached content authority must open Ready"),
        };
        let mut ready = operation.ready;
        fixture.store.conn.execute(|conn| {
            conn.execute(
                "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                [persisted_oid().to_string()],
            )
            .unwrap();
        });
        let result = ready.finish(
            (),
            &ResolutionCompletion::Complete,
            &CancellationToken::default(),
        );
        assert!(matches!(
            result.unwrap(),
            SelectedResolutionOperationOutcome::Stale(
                SelectedResolutionStale::MountInventoryChanged
            )
        ));
    }
    #[test]
    fn cancelled_or_final_stale_broad_attempt_rolls_back_and_retries_exactly() {
        let fixture = ResolutionOperationFixture::new();
        let masks = fixture.parity_masks();
        let oracle_token = CancellationToken::default();
        let oracle_operation = fixture.open_parity_ready(&masks, &oracle_token);
        let oracle = PreloadedOracle::from_operation(&fixture, &oracle_operation);
        drop(oracle_operation);
        let mut expected_batches = Vec::new();
        let expected_summary = oracle
            .service
            .stage_all_reference_batches(2, &oracle_token, &mut |batch| {
                expected_batches.push(batch.clone());
                Ok(())
            })
            .unwrap();

        let stale_token = CancellationToken::default();
        let stale_operation = fixture.open_parity_ready(&masks, &stale_token);
        let stale_placements = contexts_for(&fixture, stale_operation.mounts().unwrap());
        let generation = fixture.project.generation_handle();
        let (stale_stager, stale_state) =
            RollbackStager::with_first_stage_hook(Box::new(move || {
                generation.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }));
        let mut metrics = SelectedResolutionContextMetrics;
        let stale = stale_operation
            .stage_selected_reference_batches(
                stale_placements,
                2,
                &stale_token,
                &mut metrics,
                stale_stager,
            )
            .unwrap();
        assert!(matches!(
            stale,
            SelectedResolutionOperationOutcome::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: 0,
                    actual: 1
                }
            )
        ));
        assert_eq!(stale_state.borrow().rollback_count, 1);
        assert_eq!(stale_state.borrow().publish_count, 0);
        assert!(stale_state.borrow().staged.is_empty());

        let retry_token = CancellationToken::default();
        let retry_operation = fixture.open_parity_ready(&masks, &retry_token);
        let retry_placements = contexts_for(&fixture, retry_operation.mounts().unwrap());
        let (retry_stager, retry_state) = RollbackStager::new();
        let mut metrics = SelectedResolutionContextMetrics;
        let retry = retry_operation
            .stage_selected_reference_batches(
                retry_placements,
                2,
                &retry_token,
                &mut metrics,
                retry_stager,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(retry) = retry else {
            panic!("unchanged retry after final stale must publish natively")
        };
        assert_eq!(retry_state.borrow().rollback_count, 0);
        assert_eq!(retry_state.borrow().publish_count, 1);
        assert_semantic_summary_eq(&retry.summary, &expected_summary);
        assert_eq!(
            canonical_broad_rows(&retry.batches),
            canonical_broad_rows(&expected_batches)
        );

        let cancelled_token = CancellationToken::default();
        let cancelled_operation = fixture.open_parity_ready(&masks, &cancelled_token);
        let cancelled_placements = contexts_for(&fixture, cancelled_operation.mounts().unwrap());
        let cancellation_trigger = cancelled_token.clone();
        let (cancelled_stager, cancelled_state) =
            RollbackStager::with_first_stage_hook(Box::new(move || {
                cancellation_trigger.cancel();
                Ok(())
            }));
        let mut metrics = SelectedResolutionContextMetrics;
        let cancelled = cancelled_operation
            .stage_selected_reference_batches(
                cancelled_placements,
                2,
                &cancelled_token,
                &mut metrics,
                cancelled_stager,
            )
            .unwrap();
        assert!(matches!(
            cancelled,
            SelectedResolutionOperationOutcome::Cancelled(_)
        ));
        assert_eq!(cancelled_state.borrow().rollback_count, 1);
        assert_eq!(cancelled_state.borrow().publish_count, 0);
        assert!(cancelled_state.borrow().staged.is_empty());

        let cancellation_retry_token = CancellationToken::default();
        let cancellation_retry_operation =
            fixture.open_parity_ready(&masks, &cancellation_retry_token);
        let cancellation_retry_placements =
            contexts_for(&fixture, cancellation_retry_operation.mounts().unwrap());
        let (cancellation_retry_stager, cancellation_retry_state) = RollbackStager::new();
        let mut metrics = SelectedResolutionContextMetrics;
        let cancellation_retry = cancellation_retry_operation
            .stage_selected_reference_batches(
                cancellation_retry_placements,
                2,
                &cancellation_retry_token,
                &mut metrics,
                cancellation_retry_stager,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(cancellation_retry) = cancellation_retry
        else {
            panic!("unchanged retry after cancellation must publish natively")
        };
        assert_eq!(cancellation_retry_state.borrow().rollback_count, 0);
        assert_eq!(cancellation_retry_state.borrow().publish_count, 1);
        assert_semantic_summary_eq(&cancellation_retry.summary, &expected_summary);
        assert_eq!(
            canonical_broad_rows(&cancellation_retry.batches),
            canonical_broad_rows(&expected_batches)
        );
    }
    #[test]
    fn fallback_is_whole_operation_only_for_unavailable_or_stale() {
        let fixture = ResolutionOperationFixture::new();
        let effects = Rc::new(RefCell::new(Vec::new()));
        let cancellation = CancellationToken::default();
        let empty_snapshots = WorkspaceSnapshots::default();
        let empty_masks = Vec::new();
        let initial_unavailable = fixture
            .store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &fixture.project,
                    &fixture.workspace_id,
                    &empty_snapshots,
                    &fixture.languages,
                    &empty_masks,
                ),
                &cancellation,
            )
            .unwrap();
        let unavailable_effects = Rc::clone(&effects);
        let initial_unavailable = initial_unavailable
            .with_legacy(&cancellation, move || {
                unavailable_effects.borrow_mut().push("initial-unavailable");
                Ok(11_usize)
            })
            .unwrap();
        assert!(matches!(
            initial_unavailable,
            SelectedResolutionOperationOpenResult::Legacy {
                value: 11,
                reason: SelectedResolutionFallbackReason::Unavailable(
                    SelectedResolutionUnavailable::MissingWorkspaceSnapshot { .. }
                )
            }
        ));

        let stale_masks = fixture.parity_masks();
        let stale_input = SelectedResolutionOperationInput::new(
            &fixture.project,
            &fixture.workspace_id,
            &fixture.snapshots,
            &fixture.languages,
            &stale_masks,
        )
        .with_content_mounts(vec![fixture.counterfactual_content(
            PROVIDER_PATH,
            RICH_JAVA_SOURCE,
            PROVIDER_JAVA_SOURCE,
        )]);
        fixture.project.advance();
        let initial_stale = fixture
            .store
            .open_selected_resolution_operation(stale_input, &cancellation)
            .unwrap();
        let stale_effects = Rc::clone(&effects);
        let initial_stale = initial_stale
            .with_legacy(&cancellation, move || {
                stale_effects.borrow_mut().push("initial-stale");
                Ok(12_usize)
            })
            .unwrap();
        assert!(matches!(
            initial_stale,
            SelectedResolutionOperationOpenResult::Legacy {
                value: 12,
                reason: SelectedResolutionFallbackReason::Stale(
                    SelectedResolutionStale::TransientAnalysisGeneration {
                        expected: 0,
                        actual: 1
                    }
                )
            }
        ));

        let final_stale_operation = fixture.open_parity_ready(&stale_masks, &cancellation);
        let final_stale_placements =
            contexts_for(&fixture, final_stale_operation.mounts().unwrap());
        let generation = fixture.project.generation_handle();
        let (final_stale_stager, final_stale_state) =
            CountRollbackStager::with_first_stage_hook(Box::new(move || {
                generation.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }));
        let mut metrics = SelectedResolutionContextMetrics;
        let final_stale = final_stale_operation.stage_selected_reference_batches(
            final_stale_placements,
            2,
            &cancellation,
            &mut metrics,
            final_stale_stager,
        );
        let final_stale_effects = Rc::clone(&effects);
        let observed_final_stale_state = Rc::clone(&final_stale_state);
        let final_stale = dispatch_usize(final_stale, &cancellation, move || {
            let state = observed_final_stale_state.borrow();
            assert_eq!(state.rollback_count, 1);
            assert_eq!(state.publish_count, 0);
            assert!(state.staged.is_empty());
            drop(state);
            final_stale_effects.borrow_mut().push("final-stale");
            Ok(13)
        })
        .unwrap();
        assert!(matches!(
            final_stale,
            SelectedResolutionOperationResult::Legacy {
                value: 13,
                reason: SelectedResolutionFallbackReason::Stale(
                    SelectedResolutionStale::TransientAnalysisGeneration {
                        expected: 1,
                        actual: 2
                    }
                )
            }
        ));

        let cancelled_token = CancellationToken::default();
        let cancelled_operation = fixture.open_parity_ready(&stale_masks, &cancelled_token);
        let cancelled_placements = contexts_for(&fixture, cancelled_operation.mounts().unwrap());
        let cancellation_trigger = cancelled_token.clone();
        let (cancelled_stager, cancelled_state) =
            CountRollbackStager::with_first_stage_hook(Box::new(move || {
                cancellation_trigger.cancel();
                Ok(())
            }));
        let mut metrics = SelectedResolutionContextMetrics;
        let cancelled = cancelled_operation.stage_selected_reference_batches(
            cancelled_placements,
            2,
            &cancelled_token,
            &mut metrics,
            cancelled_stager,
        );
        let cancelled_effects = Rc::clone(&effects);
        let cancelled = dispatch_usize(cancelled, &cancelled_token, move || {
            cancelled_effects.borrow_mut().push("forbidden-cancelled");
            Ok(14)
        })
        .unwrap();
        assert!(matches!(
            cancelled,
            SelectedResolutionOperationResult::Cancelled(_)
        ));
        assert_eq!(cancelled_state.borrow().rollback_count, 1);
        assert_eq!(cancelled_state.borrow().publish_count, 0);

        let error_token = CancellationToken::default();
        let error_operation = fixture.open_parity_ready(&stale_masks, &error_token);
        let error_placements = contexts_for(&fixture, error_operation.mounts().unwrap());
        let (error_stager, error_state) =
            CountRollbackStager::with_first_stage_hook(Box::new(|| {
                Err(StoreError::new("injected broad staging failure"))
            }));
        let mut metrics = SelectedResolutionContextMetrics;
        let error_attempt = error_operation.stage_selected_reference_batches(
            error_placements,
            2,
            &error_token,
            &mut metrics,
            error_stager,
        );
        let error_effects = Rc::clone(&effects);
        let error = dispatch_usize(error_attempt, &error_token, move || {
            error_effects.borrow_mut().push("forbidden-error");
            Ok(15)
        });
        let error = match error {
            Err(error) => error,
            Ok(_) => panic!("store errors are direct and cannot authorize legacy"),
        };
        assert!(error.to_string().contains("injected broad staging failure"));
        assert_eq!(error_state.borrow().rollback_count, 1);
        assert_eq!(error_state.borrow().publish_count, 0);

        let native_token = CancellationToken::default();
        let native_operation = fixture.open_parity_ready(&stale_masks, &native_token);
        let native_placements = contexts_for(&fixture, native_operation.mounts().unwrap());
        let (native_stager, native_state) =
            CountRollbackStager::with_first_stage_hook(Box::new(|| Ok(())));
        let mut metrics = SelectedResolutionContextMetrics;
        let native = native_operation.stage_selected_reference_batches(
            native_placements,
            2,
            &native_token,
            &mut metrics,
            native_stager,
        );
        let native_effects = Rc::clone(&effects);
        let native = dispatch_usize(native, &native_token, move || {
            native_effects.borrow_mut().push("forbidden-native");
            Ok(16)
        })
        .unwrap();
        assert!(matches!(
            native,
            SelectedResolutionOperationResult::Native(reference_count) if reference_count > 0
        ));
        assert_eq!(native_state.borrow().rollback_count, 0);
        assert_eq!(native_state.borrow().publish_count, 1);
        assert_eq!(
            effects.borrow().as_slice(),
            ["initial-unavailable", "initial-stale", "final-stale"]
        );
    }
    /// A crate stage checks each mount's publication once
    /// (`resolution_authority::AuthorityValidations`). A republication after that
    /// check is not seen by the stage's later reads of the mount, but the graph
    /// build's `finish_native` still ends the request `Stale`.
    #[test]
    fn a_republication_during_a_crate_stage_still_ends_stale() {
        use brokk_bifrost_analysis::analyzer::store::resolution_authority::SelectedResolutionAuthority;
        let fixture = ResolutionOperationFixture::new();
        let cancellation = CancellationToken::default();
        let mut operation = fixture.open_ready(&[], Vec::new(), &cancellation);
        {
            let _memos = operation.crate_stage_memos().unwrap();
            let inventory = &operation.ready.inventory;
            let authority = SelectedResolutionAuthority::new(
                inventory.connection(),
                inventory.shared_name_table(),
                inventory.requested_mount_rows(),
                inventory.persisted_mount_count(),
                inventory.authority_validations(),
                inventory.authority_request_memo(),
            );
            let mount = inventory.mounts().unwrap()[0].clone();
            assert_eq!(
                authority.ensure_authority(&mount, &cancellation).unwrap(),
                Some(())
            );
            let blob = mount.blob_id();
            let republished = fixture.store.conn.execute(move |conn| {
                conn.execute(
                    "UPDATE resolution_fragment_interiors SET publication_state = 'building' \
                 WHERE blob_id = ?1",
                    [blob],
                )
                .unwrap()
            });
            assert_eq!(republished, 1);
            assert_eq!(
                authority.ensure_authority(&mount, &cancellation).unwrap(),
                Some(()),
                "the stage relies on its first check of the mount"
            );
        }
        let outcome = operation
            .finish_native((), &ResolutionCompletion::Complete, &cancellation)
            .unwrap();
        match outcome {
            SelectedResolutionOperationOutcome::Stale(reason) => {
                assert_eq!(reason, SelectedResolutionStale::MountInventoryChanged)
            }
            _ => panic!("a republication during the stage must end Stale"),
        }
    }
    #[test]
    fn selected_operation_memoizes_published_authority_identities_and_site_rows() {
        use brokk_bifrost_analysis::analyzer::store::resolution_authority::SelectedResolutionAuthority;

        let fixture = ResolutionOperationFixture::new();
        let cancellation = CancellationToken::default();
        begin_production_selected_sql_trace(&fixture.store);
        let mut operation_costs = Vec::new();
        for _ in 0..2 {
            let operation = fixture.open_ready(&[], Vec::new(), &cancellation);
            let inventory = &operation.ready.inventory;
            let mount = inventory.mounts().unwrap()[0].clone();
            let (node_key, semantic_key, site_key) = inventory
            .connection()
            .query_row(
                "SELECT (SELECT local_key FROM resolution_node_catalog WHERE blob_id=?1 ORDER BY local_key LIMIT 1), (SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND identity_digest IS NOT NULL ORDER BY local_key LIMIT 1), (SELECT site FROM resolution_sites WHERE blob_id=?1 AND role=1 ORDER BY site LIMIT 1)",
                [mount.blob_id()],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .unwrap();
            let node_key = u32::try_from(node_key.expect("fixture node identity"))
                .expect("fixture node key fits u32");
            let semantic_key = u32::try_from(semantic_key.expect("fixture semantic identity"))
                .expect("fixture semantic key fits u32");
            let site_key = u32::try_from(site_key.expect("fixture definition site"))
                .expect("fixture site key fits u32");
            let _setup = checkpoint_production_selected_sql_trace();

            let authority = SelectedResolutionAuthority::from_selection(inventory);
            let node = BindingNodeId::local(mount.ordinal().get(), node_key);
            let node_first = authority
                .node_catalog_provenance(node, &cancellation)
                .unwrap();
            let node_second = authority
                .node_catalog_provenance(node, &cancellation)
                .unwrap();
            assert!(node_first.as_ref().is_some_and(Option::is_some));
            assert_eq!(node_first, node_second);

            let semantic = SemanticId::local(mount.ordinal().get(), semantic_key);
            let semantic_first = authority
                .semantic_catalog_provenance(semantic, &cancellation)
                .unwrap();
            let semantic_second = authority
                .semantic_catalog_provenance(semantic, &cancellation)
                .unwrap();
            assert!(semantic_first.as_ref().is_some_and(Option::is_some));
            assert_eq!(semantic_first, semantic_second);

            let lexical = operation.ready.lexical_source();
            let requests = [
                (
                    mount.ordinal(),
                    BindingNodeId::local(mount.ordinal().get(), site_key),
                ),
                (
                    mount.ordinal(),
                    BindingNodeId::local(mount.ordinal().get(), u32::MAX),
                ),
            ];
            let sites_first = lexical
                .definition_source_sites(&requests, &cancellation)
                .unwrap()
                .unwrap();
            let sites_second = lexical
                .definition_source_sites(&requests, &cancellation)
                .unwrap()
                .unwrap();
            assert_eq!(sites_first[0], Some(ResolutionSiteId::new(site_key)));
            assert_eq!(sites_first[1], None);
            assert_eq!(sites_first, sites_second);
            operation_costs.push(checkpoint_production_selected_sql_trace());
        }
        let _cleanup = finish_production_selected_sql_trace(&fixture.store);

        for cost in operation_costs {
            let executions = |prefix: &str| {
                cost.statements
                    .iter()
                    .filter(|sql| sql.starts_with(prefix))
                    .count()
            };
            assert_eq!(
                executions("SELECT 1 FROM resolution_fragment_interiors"),
                1,
                "one published mount is checked once per operation: {:?}",
                cost.statements
            );
            assert_eq!(
                executions("SELECT identity_digest FROM resolution_node_catalog"),
                1,
                "one node identity is read once per operation: {:?}",
                cost.statements
            );
            assert_eq!(
                executions(
                    "SELECT identity_digest, shared_identity FROM resolution_semantic_catalog"
                ),
                1,
                "one semantic identity is read once per operation: {:?}",
                cost.statements
            );
            assert_eq!(
                executions("SELECT site, role, namespace, site_kind"),
                1,
                "positive and negative site keys share one memoized batch read per operation: {:?}",
                cost.statements
            );
        }
    }
    /// A crate stage holds one read transaction on its reader. Temp writes nest
    /// in it as savepoints, the request's own publication is seen only after the
    /// stage's snapshot is renewed, and the reader leaves the stage outside any
    /// transaction.
    #[test]
    fn a_crate_stage_reads_one_snapshot_and_renews_it_around_a_publication() {
        let fixture = ResolutionOperationFixture::new();
        let cancellation = CancellationToken::default();
        let operation = fixture.open_ready(&[], Vec::new(), &cancellation);
        let inventory = &operation.ready.inventory;
        let digest = [0x5a_u8; 32];
        let seen = |conn: &rusqlite::Connection| -> i64 {
            conn.query_row(
                "SELECT count(*) FROM resolution_identities WHERE identity_digest = ?1",
                [digest.as_slice()],
                |row| row.get(0),
            )
            .unwrap()
        };
        {
            let _memos = operation.crate_stage_memos().unwrap();
            assert!(!inventory.connection().is_autocommit());
            assert_eq!(seen(inventory.connection()), 0);
            inventory
            .with_owned_temp_transaction(|conn| {
                conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS stage_probe(value INTEGER)")?;
                conn.execute("INSERT INTO temp.stage_probe VALUES(1)", [])?;
                Ok(
                    brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction::Commit(
                        (),
                    ),
                )
            })
            .unwrap();
            assert!(
                !inventory.connection().is_autocommit(),
                "a temp write is a savepoint inside the stage"
            );
            fixture.store.conn.execute(move |conn| {
                conn.execute(
                    "INSERT INTO resolution_identities(identity_digest) VALUES(?1)",
                    [digest.as_slice()],
                )
                .unwrap();
            });
            assert_eq!(
                seen(inventory.connection()),
                0,
                "the stage reads its own snapshot"
            );
            inventory.pause_stage_read().unwrap();
            inventory.resume_stage_read().unwrap();
            assert_eq!(
                seen(inventory.connection()),
                1,
                "the renewed snapshot sees it"
            );
        }
        assert!(inventory.connection().is_autocommit());
        let probe: i64 = inventory
            .connection()
            .query_row("SELECT count(*) FROM temp.stage_probe", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(probe, 1, "the stage committed its temp write");
    }
    #[cfg(test)]
    fn parsed_java_state(
        project_root: &Path,
        relative_path: &str,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        parsed_operation_state(project_root, relative_path, RICH_JAVA_SOURCE, &JavaAdapter)
    }
    #[cfg(test)]
    struct ResolutionOperationFixture {
        store: AnalyzerStore,
        _project_root: tempfile::TempDir,
        project: MutableGenerationProject,
        workspace_id: WorkspaceId,
        snapshots: WorkspaceSnapshots,
        languages: Vec<SelectedResolutionLanguage>,
        generation: GenerationId,
        source_facts: FileResolutionFacts,
        provider_facts: FileResolutionFacts,
    }
    #[cfg(test)]
    impl ResolutionOperationFixture {
        fn new() -> Self {
            let project_root = tempfile::tempdir().expect("operation test project root");
            let project = MutableGenerationProject::new(project_root.path(), Language::Java);
            let store = AnalyzerStore::open_ephemeral().expect("operation test store");
            let generation = store
                .ensure_language_epoch_value("java", "resolution-operation-test-v1")
                .expect("operation test language epoch");
            store
                .ensure_resolution_producer_epoch("java", Language::Java)
                .expect("operation test producer epoch");

            let (state, source_facts) = parsed_java_state(project_root.path(), SOURCE_PATH);
            let (_, provider_facts) = parsed_operation_source_state(
                project_root.path(),
                PROVIDER_PATH,
                PROVIDER_JAVA_SOURCE,
                &JavaAdapter,
            );
            let prepared = AnalyzerStore::prepare_parsed_blob(
                persisted_oid(),
                "java",
                generation,
                &JavaAdapter,
                state,
            )
            .expect("prepare operation Java blob through the production path");
            let (outcomes, _) =
                store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
            assert_eq!(outcomes.len(), 1);
            assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);
            let workspace_id = WorkspaceId(WORKSPACE_ID.to_owned());
            let file_versions = [
                SOURCE_PATH,
                PROVIDER_PATH,
                REMOVED_PATH,
                SECOND_REPLACEMENT_PATH,
            ]
            .into_iter()
            .enumerate()
            .map(|(ordinal, path)| {
                (
                    path.to_owned(),
                    persisted_oid().to_string(),
                    format!("{:064x}", ordinal + 1),
                )
            })
            .collect();
            let snapshots = persist_test_workspace_snapshot(
                &store,
                &workspace_id,
                "java",
                generation,
                file_versions,
            );
            Self {
                store,
                _project_root: project_root,
                project,
                workspace_id,
                snapshots,
                languages: vec![SelectedResolutionLanguage::new("java", Language::Java)],
                generation,
                source_facts,
                provider_facts,
            }
        }

        fn provider_replacement(&self) -> SelectedResolutionContentMountRequest {
            self.counterfactual_content(PROVIDER_PATH, RICH_JAVA_SOURCE, PROVIDER_JAVA_SOURCE)
        }

        fn published_content(
            &self,
            path: &str,
            source: &str,
        ) -> SelectedResolutionContentMountRequest {
            use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;
            let (state, _) = parsed_operation_source_state(
                self._project_root.path(),
                path,
                source,
                &JavaAdapter,
            );
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                .expect("hash actual Java fixture content");
            let prepared = AnalyzerStore::prepare_parsed_blob(
                oid,
                "java",
                self.generation,
                &JavaAdapter,
                state,
            )
            .expect("prepare actual Java fixture content");
            let ResolutionContentPublicationOutcome::Ready(content) = self
                .store
                .publish_selected_parsed_content(
                    self.snapshots.get("java").expect("captured Java owner"),
                    path,
                    prepared,
                    &CancellationToken::default(),
                )
                .expect("publish complete Java fixture content")
            else {
                panic!("uncancelled actual Java fixture publication must succeed");
            };
            content_mount_request(content.into_parts().0, path, oid)
        }

        fn live_content(&self, path: &str, source: &str) -> SelectedResolutionContentMountRequest {
            self.published_content(path, source)
                .with_live_overlay_content_digest(
                    brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes()),
                )
        }

        fn counterfactual_content(
            &self,
            path: &str,
            original: &str,
            source: &str,
        ) -> SelectedResolutionContentMountRequest {
            counterfactual_content_mount(self.published_content(path, source), original)
        }

        fn content_mount(&self, path: &str) -> SelectedResolutionContentMountRequest {
            use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentInput;

            use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;
            let outcome = self
                .store
                .admit_cached_selected_content(
                    &self.snapshots["java"],
                    path,
                    persisted_oid(),
                    &ResolutionContentInput::Parsed {
                        content_oid: persisted_oid(),
                        semantic_language: Language::Java,
                    },
                    &CancellationToken::default(),
                )
                .unwrap();
            let ResolutionContentPublicationOutcome::Ready(content) = outcome else {
                panic!("real content fixture publication: {outcome:?}");
            };
            content_mount_request(content.into_parts().0, path, persisted_oid())
        }

        fn second_replacement(&self) -> SelectedResolutionContentMountRequest {
            self.counterfactual_content(SECOND_REPLACEMENT_PATH, RICH_JAVA_SOURCE, RICH_JAVA_SOURCE)
        }

        fn parity_masks(&self) -> Vec<SelectedResolutionOverlayMask> {
            vec![
                SelectedResolutionOverlayMask::replacement("java", PROVIDER_PATH),
                SelectedResolutionOverlayMask::removal("java", REMOVED_PATH),
                SelectedResolutionOverlayMask::removal("java", SECOND_REPLACEMENT_PATH),
            ]
        }

        fn two_replacement_masks(&self) -> Vec<SelectedResolutionOverlayMask> {
            vec![
                SelectedResolutionOverlayMask::replacement("java", PROVIDER_PATH),
                SelectedResolutionOverlayMask::removal("java", REMOVED_PATH),
                SelectedResolutionOverlayMask::replacement("java", SECOND_REPLACEMENT_PATH),
            ]
        }

        fn open<'a>(
            &'a self,
            masks: &'a [SelectedResolutionOverlayMask],
            replacements: Vec<SelectedResolutionContentMountRequest>,
            cancellation: &CancellationToken,
        ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
            self.store.open_selected_resolution_operation(
                selected_operation_input(
                    &self.project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    masks,
                    replacements,
                ),
                cancellation,
            )
        }

        fn open_ready<'a>(
            &'a self,
            masks: &'a [SelectedResolutionOverlayMask],
            replacements: Vec<SelectedResolutionContentMountRequest>,
            cancellation: &CancellationToken,
        ) -> SelectedResolutionOperation<'a, 'a> {
            open_ready_operation(
                &self.store,
                selected_operation_input(
                    &self.project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    masks,
                    replacements,
                ),
                cancellation,
            )
        }

        fn open_with_project_and_content_mounts<'a>(
            &'a self,
            project: &'a dyn Project,
            masks: &'a [SelectedResolutionOverlayMask],
            content_mounts: Vec<SelectedResolutionContentMountRequest>,
            cancellation: &CancellationToken,
        ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
            self.store.open_selected_resolution_operation(
                selected_operation_input(
                    project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    masks,
                    content_mounts,
                ),
                cancellation,
            )
        }

        fn open_parity_ready<'a>(
            &'a self,
            masks: &'a [SelectedResolutionOverlayMask],
            cancellation: &CancellationToken,
        ) -> SelectedResolutionOperation<'a, 'a> {
            self.open_ready(masks, vec![self.provider_replacement()], cancellation)
        }
    }
    #[cfg(test)]
    fn contexts_for(
        _fixture: &ResolutionOperationFixture,
        mounts: &[SelectedResolutionOperationMount],
    ) -> SelectedResolutionContextSet {
        // A context set is sparse, so a context with no relation and no inventory
        // evidence is empty whatever the operation selected.
        SelectedResolutionContextSet::new(
            SelectedContextIdentities::new(),
            Vec::new(),
            mounts.len(),
            &mount_lookup(mounts),
        )
        .expect("exact Java operation context set")
    }
    #[cfg(test)]
    struct PreloadedOracle {
        service: PreloadedFactResolutionService,
        // Preserve the original shared fixture construction and read work.
        #[allow(dead_code)]
        point_reference: brokk_bifrost_analysis::analyzer::resolution::model::SemanticId,
        // Preserve the original shared fixture construction and read work.
        #[allow(dead_code)]
        reverse_definition: brokk_bifrost_analysis::analyzer::resolution::model::SemanticId,
        // Preserve the original shared fixture construction and read work.
        #[allow(dead_code)]
        source_fragment: brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId,
        // Preserve the original shared fixture construction and read work.
        #[allow(dead_code)]
        provider_fragment: brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId,
    }
    #[cfg(test)]
    impl PreloadedOracle {
        fn from_operation(
            fixture: &ResolutionOperationFixture,
            operation: &SelectedResolutionOperation<'_, '_>,
        ) -> Self {
            assert_eq!(operation.mount_table().mount_count(), 2);
            let lowered = operation
            .mounts()
            .unwrap()
            .iter()
            .map(|mount| {
                let facts = match mount.persisted_relative_path() {
                    SOURCE_PATH => &fixture.source_facts,
                    PROVIDER_PATH => &fixture.provider_facts,
                    path => panic!("unexpected parity mount {path:?}"),
                };
                (mount.persisted_relative_path().to_owned(), {
                    let artifact =
                        brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                            mount.fragment(),
                            &operation.ready.shared_names(),
                            Language::Java,
                            facts,
                        );
                    brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::record_selected(
                        artifact.identities(),
                        operation
                            .ready
                            .inventory
                            .mount_record_by_ordinal(mount.ordinal())
                            .unwrap()
                            .fragment_digest()
                            .as_bytes(),
                    );
                    artifact
                })
            })
            .collect::<Vec<_>>();
            let source = lowered
                .iter()
                .find(|(path, _)| path == SOURCE_PATH)
                .expect("persisted source artifact");
            let provider = lowered
                .iter()
                .find(|(path, _)| path == PROVIDER_PATH)
                .expect("transient provider artifact");
            let point_site = site_for_identifier(
                &fixture.source_facts,
                "method",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Callable,
            );
            let definition_site = provider_method_site(&fixture.provider_facts);
            let point_reference =
                semantic_at(&source.1, point_site, LoweredSemanticRole::Reference);
            let reverse_definition = semantic_at(
                &provider.1,
                definition_site,
                LoweredSemanticRole::Definition,
            );
            let source_fragment = source.1.lexical().fragment();
            let provider_fragment = provider.1.lexical().fragment();
            let mut service = PreloadedFactResolutionService::from_lowered_fragments(
                lowered
                    .iter()
                    .map(|(_, artifact)| artifact.lexical().clone()),
                lowered.iter().map(|(_, artifact)| artifact.typed().clone()),
            );
            // The persisted operation reads Java inheritance declarations from its
            // indexed source rows. Install the same facts from the lowered member
            // scopes so the preloaded oracle runs the same Java hierarchy replay.
            // These fixtures author classes only, each in one known package.
            let mut declarations = Vec::new();
            for (path, artifact) in &lowered {
                let (text, package) = match path.as_str() {
                    SOURCE_PATH => (RICH_JAVA_SOURCE, "com.acme"),
                    PROVIDER_PATH => (PROVIDER_JAVA_SOURCE, "dep"),
                    path => panic!("unexpected parity mount {path:?}"),
                };
                assert!(text.contains(&format!("package {package};")), "{path}");
                assert!(!text.contains("interface"), "{path}");
                declarations.extend(
                artifact
                    .typed()
                    .member_scopes()
                    .iter()
                    .filter(|row| row.is_type_body())
                    .map(
                        |row| brokk_bifrost_analysis::analyzer::resolution::fact_source::JavaInheritanceDeclaration {
                            definition: row.definition(),
                            name: String::new(),
                            package: Some(package.to_owned()),
                            kind:
                                brokk_bifrost_analysis::analyzer::resolution::fact_source::JavaInheritanceDeclarationKind::Type {
                                    is_interface: false,
                                    is_singleton: false,
                                },
                        },
                    ),
            );
            }
            service.set_java_inheritance_metadata(declarations);
            Self {
                service,
                point_reference,
                reverse_definition,
                source_fragment,
                provider_fragment,
            }
        }
    }
    use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;
    use std::collections::HashSet;

    #[test]
    fn reverse_candidate_static_extension_preserves_groups_and_cleans_request_keys() {
        use brokk_bifrost_analysis::analyzer::resolution::{SharedNameId, SharedNameInterner};
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse_candidates::{
            REVERSE_LOOKUP_IDENTITY_ARM_SQL, ReverseCandidateKey, ReverseContextWitness,
            ReverseNominationRoute, read_reverse_candidates, read_reverse_candidates_with_arms,
        };
        static ARMS: &[&str] = &[REVERSE_LOOKUP_IDENTITY_ARM_SQL];
        let fixture = ResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        // The shared fixture is Java after Rust's harness moved to tools. Stage
        // source identities from its published paths to exercise the opt-in join.
        fixture.store.conn.lock().unwrap().execute("INSERT OR IGNORE INTO resolution_reference_lookup_identities(blob_id,semantic_key,identity_id)
        SELECT path.blob_id,reference.semantic_key,path.end_lead_identity
        FROM resolution_paths path JOIN resolution_semantic_sites reference
          ON reference.blob_id=path.blob_id AND reference.source_site=path.start_node
          AND reference.semantic_role='reference'
        WHERE path.end_lead_identity>0", []).unwrap();
        let operation = fixture.open_ready(&[], Vec::new(), &cancellation);
        let conn = operation.ready.inventory.connection();
        let (ordinal,blob,lookup): (u32,i64,i64) = conn.query_row(
            "SELECT mounts.mount_ordinal,names.blob_id,names.identity_id FROM temp.selected_resolution_mounts mounts
         JOIN resolution_reference_lookup_identities names ON names.blob_id=mounts.blob_id
         ORDER BY mounts.mount_ordinal,names.semantic_key LIMIT 1",[],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))
        ).unwrap();
        let lookup = SemanticId::shared_name(
            operation
                .ready
                .shared_names()
                .from_persisted(SharedNameId::interned(lookup)),
        );
        let context = ReverseContextWitness::new(&operation, ordinal, blob);
        let missing = ResolutionLookupSemanticRecipe::new(
            Language::Java,
            ResolutionNamespace::Value,
            "absent_lookup_request_key",
        )
        .semantic(&operation.ready.shared_names());
        let keys = [(2, lookup), (5, lookup), (8, missing)].map(|(input_ordinal, lookup)| {
            ReverseCandidateKey {
                input_ordinal,
                context: context.clone(),
                lookup,
                root: true,
                lexical: true,
                qualified: true,
            }
        });
        let base = read_reverse_candidates(&operation, &keys, &cancellation)
            .unwrap()
            .unwrap();
        let extended = read_reverse_candidates_with_arms(&operation, &keys, ARMS, &cancellation)
            .unwrap()
            .unwrap();
        assert_eq!(extended.len(), 3);
        assert!(extended[2].is_empty());
        let persisted_lookup = operation
            .ready
            .shared_names()
            .to_persisted(lookup.shared_name_id().unwrap())
            .unwrap()
            .get();
        let extra = conn.prepare("SELECT reference.source_site FROM resolution_reference_lookup_identities names
         JOIN resolution_semantic_sites reference ON reference.blob_id=names.blob_id AND reference.semantic_role='reference' AND reference.semantic_key=names.semantic_key
         WHERE names.blob_id=?1 AND names.identity_id=?2").unwrap()
             .query_map(rusqlite::params![blob,persisted_lookup],|row|row.get::<_,u32>(0)).unwrap()
             .collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert!(!extra.is_empty());
        for position in 0..2 {
            let mut expected = base[position]
                .iter()
                .map(|row| (row.site.get(), row.route))
                .collect::<HashSet<_>>();
            expected.extend(
                extra
                    .iter()
                    .map(|site| (*site, ReverseNominationRoute::Lookup)),
            );
            assert_eq!(
                extended[position]
                    .iter()
                    .map(|row| (row.site.get(), row.route))
                    .collect::<HashSet<_>>(),
                expected
            );
            assert_eq!(
                extended[position].len(),
                expected.len(),
                "duplicate nominations: {:?}",
                extended[position]
            );
            for original in &base[position] {
                let retained = extended[position]
                    .iter()
                    .find(|row| row.site == original.site && row.route == original.route)
                    .unwrap();
                assert_eq!(
                    retained.provenance, original.provenance,
                    "source inventory cannot replace an existing path witness"
                );
            }
            assert!(
                extended[position]
                    .iter()
                    .all(|row| row.input_ordinal == keys[position].input_ordinal)
            );
        }
        let count = || {
            conn.query_row(
                "SELECT count(*) FROM temp.reverse_candidate_keys",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap()
        };
        assert_eq!(count(), 0);
        assert!(
            read_reverse_candidates_with_arms(&operation, &[], ARMS, &cancellation)
                .unwrap()
                .unwrap()
                .is_empty()
        );
        assert_eq!(count(), 0);
        static MISSING_SOURCE_ARMS: &[&str] = &[
            "SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,s.site,0,0,0 FROM temp.reverse_candidate_keys k JOIN missing_reverse_source s ON s.blob_id=k.blob",
        ];
        assert!(
            read_reverse_candidates_with_arms(
                &operation,
                &keys,
                MISSING_SOURCE_ARMS,
                &cancellation
            )
            .is_err()
        );
        assert_eq!(count(), 0);
        cancellation.cancel();
        assert!(
            read_reverse_candidates_with_arms(&operation, &keys, ARMS, &cancellation)
                .unwrap()
                .is_none()
        );
        assert_eq!(count(), 0);
    }
}
