#[cfg(test)]
mod rust_departing_wave2_root_tests {
    use rusqlite::params;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStage;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStageOutcome;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;
    #[test]
    fn authenticated_capsule_admission_replays_variables_and_rolls_back_cancelled_assignment() {
        use crate::engine_tests::rust_analyzer_store_resolution_operation_tests::rust_departing_root_tests::DenseSelectedMacroFixture;
        use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

        use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

        use brokk_bifrost_analysis::analyzer::store::resolution_publication::prepare_resolution_capsule;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;

        // #5375: item inputs retain name/member frontiers, not a closable
        // invocation-wide argument gap. Exercise closure with expression inputs.
        DenseSelectedMacroFixture::with_expression_inputs(|store, owner, fixtures| {
            let live = CancellationToken::new();
            let mut cases = Vec::new();
            for mut fixture in fixtures.into_iter().take(2) {
                // Extend the actual capsule using model constructors before its
                // canonical preparation; the parsed macro has no variable itself.
                fixture.dense = fixture.dense.with_open_variable_for_publication_test();
                fixture.reordered = fixture.reordered.with_open_variable_for_publication_test();
                let prepared = prepare_resolution_capsule(
                    fixture.key.clone(),
                    fixture.checkpoint,
                    fixture.module_scope,
                    &fixture.dense,
                    &fixture.lowering,
                    fixture.host_input_start_line,
                    fixture.references.clone(),
                    &live,
                )
                .unwrap()
                .unwrap();
                let ResolutionContentPublicationOutcome::Ready(first) = store
                    .publish_selected_resolution_capsule(owner, &fixture.host_path, prepared, &live)
                    .unwrap()
                else {
                    panic!("actual capsule must publish");
                };
                let cached = || {
                    let ResolutionContentPublicationOutcome::Ready(content) = store
                        .admit_cached_selected_content(
                            owner,
                            &fixture.host_path,
                            first.witness().blob_oid(),
                            first.witness().input(),
                            &live,
                        )
                        .unwrap()
                    else {
                        panic!("published capsule must remain available");
                    };
                    content
                };
                let repeat = cached();
                let changed = cached();
                let after_clear = cached();
                cases.push((fixture, first, repeat, changed, after_clear));
            }
            assert_eq!(cases.len(), 2);
            let snapshots = WorkspaceSnapshots::from_iter([(owner.lang.clone(), owner.clone())]);
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &owner.workspace_id,
                    &snapshots,
                    &[SelectedResolutionLanguage::new(
                        owner.lang.clone(),
                        Language::Rust,
                    )],
                    &[],
                    &live,
                )
                .unwrap()
            else {
                panic!("actual macro hosts must open Ready");
            };
            let stage = SelectedResolutionStage::new(&selection);
            let mut replay_after_clear = None;
            let mut expected_closed = std::collections::BTreeSet::new();
            for (index, (fixture, first, repeat, changed, after_clear)) in
                cases.into_iter().enumerate()
            {
                let host = selection
                    .mount_record_for_path(&owner.lang, &fixture.host_path)
                    .unwrap()
                    .unwrap();
                let invocation = fixture.key.invocation;
                assert_eq!(
                    stage
                        .has_admitted_macro_input(host.ordinal(), invocation, &live)
                        .unwrap(),
                    Some(false)
                );
                let site: Option<u32> = selection.connection().query_row(
                "SELECT native_gap_site FROM source_rust_macro_inputs WHERE blob_id=?1 AND invocation_occurrence_id=?2",
                params![host.blob_id(),invocation.get()], |row| row.get(0)).unwrap();
                if let Some(site) = site {
                    let ordinary = brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource::new_on_demand(&selection);
                    for reason in ordinary
                        .unsupported_gap_reasons(
                            host.ordinal(),
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(
                                site,
                            ),
                            &live,
                        )
                        .unwrap()
                        .unwrap()
                    {
                        expected_closed.insert(brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::encode_semantic(reason));
                    }
                }
                let changed_body = fixture
                    .dense
                    .with_changed_reference_end_for_publication_test();
                if index == 0 {
                    replay_after_clear = Some((
                        after_clear,
                        host.clone(),
                        invocation,
                        fixture.dense.clone_for_stage_admission_test(),
                    ));
                }

                let before = selection.candidate_coverage_fingerprint();
                if index == 0 {
                    assert!(!fixture.dense.identities().stack_variables().is_empty());
                    assert!(matches!(
                        stage
                            .admit_capsule(*first, &host, fixture.dense, &[], &live)
                            .unwrap(),
                        SelectedResolutionStageOutcome::Ready
                    ));
                    let admitted = selection.candidate_coverage_fingerprint();
                    assert_ne!(before, admitted);
                    let other: u32 = selection.connection().query_row("SELECT mount_ordinal FROM temp.selected_resolution_mounts WHERE mount_ordinal<>?1 LIMIT 1", [host.ordinal().get()], |row|row.get(0)).unwrap();
                    assert_eq!(
                        stage
                            .has_admitted_macro_input(
                                SelectedResolutionMountOrdinal::new(other),
                                invocation,
                                &live
                            )
                            .unwrap(),
                        Some(false)
                    );
                    selection.with_owned_temp_write(|connection| {
                    connection.execute("DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=?1",[host.ordinal().get()])?;
                    Ok(())
                }).unwrap();
                    assert_eq!(
                        stage
                            .has_admitted_macro_input(host.ordinal(), invocation, &live)
                            .unwrap(),
                        Some(true)
                    );
                    selection.with_owned_temp_write(|connection| {
                    connection.execute("INSERT INTO temp.selected_resolution_scope_mounts(mount_ordinal) VALUES(?1)",[host.ordinal().get()])?;
                    Ok(())
                }).unwrap();
                    let variables: String = selection.connection().query_row(
                    "SELECT json_group_array(json_array(producer_id,dense_key,runtime_key,hex(identity_digest))) FROM (SELECT * FROM temp.selected_resolution_stage_variable_coordinates ORDER BY producer_id,dense_key)",
                    [], |row| row.get(0)).unwrap();
                    let changes = selection.connection().total_changes();
                    assert!(matches!(
                        stage
                            .admit_capsule(*repeat, &host, fixture.reordered, &[], &live)
                            .unwrap(),
                        SelectedResolutionStageOutcome::Ready
                    ));
                    assert_eq!(selection.connection().total_changes(), changes);
                    assert_eq!(selection.candidate_coverage_fingerprint(), admitted);
                    assert_eq!(selection.connection().query_row(
                    "SELECT json_group_array(json_array(producer_id,dense_key,runtime_key,hex(identity_digest))) FROM (SELECT * FROM temp.selected_resolution_stage_variable_coordinates ORDER BY producer_id,dense_key)",
                    [], |row| row.get::<_,String>(0)).unwrap(), variables);
                    assert!(
                        stage
                            .admit_capsule(*changed, &host, changed_body, &[], &live)
                            .is_err()
                    );
                    assert_eq!(selection.candidate_coverage_fingerprint(), admitted);
                } else {
                    let counters: String = selection.connection().query_row(
                    "SELECT json_group_array(json_array(host_ordinal,domain,next_key)) FROM (SELECT * FROM temp.selected_resolution_stage_allocation_counters ORDER BY host_ordinal,domain)",
                    [], |row| row.get(0)).unwrap();
                    let cancel = CancellationToken::new();
                    let trigger_cancel = cancel.clone();
                    selection
                        .connection()
                        .create_scalar_function(
                            "cancel_capsule_projection",
                            0,
                            rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                            move |_| {
                                trigger_cancel.cancel();
                                Ok(0)
                            },
                        )
                        .unwrap();
                    selection.with_owned_temp_write(|connection| {
                    connection.execute_batch("CREATE TEMP TRIGGER cancel_capsule_projection AFTER INSERT ON selected_resolution_stage_producers BEGIN SELECT cancel_capsule_projection(); END;")?;
                    Ok(())
                }).unwrap();
                    assert!(matches!(
                        stage
                            .admit_capsule(*first, &host, fixture.dense, &[], &cancel)
                            .unwrap(),
                        SelectedResolutionStageOutcome::Cancelled
                    ));
                    assert!(
                        cancel.is_cancelled(),
                        "cancellation occurred during actual admission DML"
                    );
                    assert!(selection.connection().is_autocommit());
                    assert_eq!(selection.candidate_coverage_fingerprint(), before);
                    assert_eq!(selection.connection().query_row(
                    "SELECT json_group_array(json_array(host_ordinal,domain,next_key)) FROM (SELECT * FROM temp.selected_resolution_stage_allocation_counters ORDER BY host_ordinal,domain)",
                    [], |row| row.get::<_,String>(0)).unwrap(), counters);
                    selection
                        .with_owned_temp_write(|connection| {
                            connection
                                .execute_batch("DROP TRIGGER temp.cancel_capsule_projection")?;
                            Ok(())
                        })
                        .unwrap();
                    selection
                        .connection()
                        .remove_function("cancel_capsule_projection", 0)
                        .unwrap();
                    assert!(matches!(
                        stage
                            .admit_capsule(*repeat, &host, fixture.reordered, &[], &live)
                            .unwrap(),
                        SelectedResolutionStageOutcome::Ready
                    ));
                    assert_ne!(selection.candidate_coverage_fingerprint(), before);
                }
                assert_eq!(
                    stage
                        .has_admitted_macro_input(host.ordinal(), invocation, &live)
                        .unwrap(),
                    Some(true)
                );
                assert_eq!(
                    stage
                        .has_admitted_macro_input(
                            SelectedResolutionMountOrdinal::new(u32::MAX >> 3),
                            invocation,
                            &live
                        )
                        .unwrap(),
                    Some(false)
                );
                let cancelled = CancellationToken::new();
                cancelled.cancel();
                assert_eq!(
                    stage
                        .has_admitted_macro_input(host.ordinal(), invocation, &cancelled)
                        .unwrap(),
                    None
                );
                let actual_closed = selection.connection().prepare("SELECT DISTINCT semantic_key FROM temp.selected_resolution_stage_closed_reasons WHERE semantic_shared IS NULL ORDER BY semantic_key").unwrap()
                .query_map([], |row| row.get::<_,i64>(0)).unwrap().collect::<rusqlite::Result<std::collections::BTreeSet<_>>>().unwrap();
                assert_eq!(
                    actual_closed, expected_closed,
                    "only exact selected invocation sites and unsupported origins close"
                );
            }
            assert!(
                !expected_closed.is_empty(),
                "real macro source contributes exact unsupported reasons"
            );
            let variables: (i64, i64, i64) = selection.connection().query_row(
            "SELECT count(*),count(DISTINCT runtime_key),count(DISTINCT identity_digest) FROM temp.selected_resolution_stage_variable_coordinates",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
            assert_eq!(
                variables,
                (2, 2, 1),
                "separate producers assign fresh variables even for the same identity"
            );
            let counters: i64 = selection
                .connection()
                .query_row(
                    "SELECT sum(next_key) FROM temp.selected_resolution_stage_allocation_counters",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            stage.clear_facts().unwrap();
            assert_eq!(
            selection
                .connection()
                .query_row(
                    "SELECT sum(next_key) FROM temp.selected_resolution_stage_allocation_counters",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            counters
        );
            let (receipt, host, invocation, dense) = replay_after_clear.unwrap();
            assert_eq!(
                stage
                    .has_admitted_macro_input(host.ordinal(), invocation, &live)
                    .unwrap(),
                Some(false),
                "retained witness is not active capsule content"
            );
            assert_eq!(
                selection
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM temp.selected_resolution_stage_closed_reasons",
                        [],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                0
            );
            let epoch = selection.stage_content_epoch_for_test();
            assert!(matches!(
                stage
                    .admit_capsule(*receipt, &host, dense, &[], &live)
                    .unwrap(),
                SelectedResolutionStageOutcome::Ready
            ));
            assert_eq!(selection.stage_content_epoch_for_test(), epoch + 1);
            assert_eq!(
                stage
                    .has_admitted_macro_input(host.ordinal(), invocation, &live)
                    .unwrap(),
                Some(true)
            );
        });
    }
}
