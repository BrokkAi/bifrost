use super::*;
use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, PartialPathId, ResolutionRegisteredIdentities,
    SelectedResolutionMountOrdinal, StackVariableId, lower_resolution_facts_for_selection,
};
use crate::analyzer::store::resolution_selection::tests::SelectionFixture;
use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

#[test]
fn stage_reference_preserves_distinct_projection_outputs_and_rejects_duplicates() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    selection.with_owned_temp_write(|connection| {
        connection.execute(
            "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)",
            params![[31u8; 32].as_slice(), [32u8; 32].as_slice()],
        )?;
        let producer = connection.last_insert_rowid();
        // One lexical reference can feed both receiver and nominal identity.
        // The two output slots must survive the temporary stage independently.
        let projection = "INSERT INTO temp.selected_resolution_stage_binding_projections(host_ordinal,producer_id,sequence,reference_key,output_slot_key,kind) VALUES(0,?1,?2,1,?3,0)";
        let route = "INSERT INTO temp.selected_resolution_stage_qualified_routes(host_ordinal,producer_id,sequence,reference_key,qualifier_slot_key,lookup_key,source_lookup_key,projection_output_slot_key,coarse_gap_reason_shared,precedence_ordinal,namespace,projection_kind) VALUES(0,?1,?2,1,2,3,4,?3,11,0,0,0)";
        for sql in [projection, route] {
            connection.execute(sql, params![producer, 0, 5])?;
            connection.execute(sql, params![producer, 1, 6])?;
            let duplicate = connection.execute(sql, params![producer, 2, 5]).unwrap_err();
            assert_eq!(duplicate.sqlite_error_code(), Some(rusqlite::ErrorCode::ConstraintViolation));
        }
        let outputs = connection.prepare(
            "SELECT output_slot_key FROM temp.selected_resolution_stage_binding_projections WHERE reference_key=1 ORDER BY output_slot_key",
        )?.query_map([], |row| row.get::<_, i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(outputs, [5, 6]);
        let route_outputs = connection.prepare(
            "SELECT projection_output_slot_key FROM temp.selected_resolution_stage_qualified_routes WHERE reference_key=1 AND precedence_ordinal=0 ORDER BY projection_output_slot_key",
        )?.query_map([], |row| row.get::<_, i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(route_outputs, outputs);
        Ok(())
    }).unwrap();
}

#[test]
fn bridge_repeat_uses_complete_descriptor_and_cancelled_dml_leaves_reader_reusable() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let names = selection
        .shared_name_table()
        .interner(selection.connection());
    let assigned = lower_resolution_facts_for_selection(
        BindingFragmentId::at_ordinal(0),
        &names,
        Language::Java,
        &FileResolutionFacts::default(),
    );
    let mut runtime = ResolutionRegisteredIdentities::new(assigned.lexical().fragment());
    for (index, &(semantic, _)) in assigned.identities().semantics().iter().enumerate() {
        runtime.assign_semantic(
            semantic,
            if semantic.shared_name_id().is_some() {
                semantic
            } else {
                SemanticId::operation_local(1000 + index as u64)
            },
        );
    }
    for (index, &(node, _)) in assigned.identities().nodes().iter().enumerate() {
        runtime.assign_node(node, BindingNodeId::operation_local(1000 + index as u64));
    }
    for (index, &(path, _)) in assigned.identities().paths().iter().enumerate() {
        runtime.assign_path(path, PartialPathId::operation_local(1000 + index as u64));
    }
    for (index, &(variable, _)) in assigned.identities().stack_variables().iter().enumerate() {
        runtime.assign_stack_variable(
            variable,
            StackVariableId::operation_local(1000 + index as u64),
        );
    }
    let assigned = assigned
        .retargeted(&runtime, &CancellationToken::new())
        .unwrap();
    let stage = SelectedResolutionStage::new(&selection);
    let insert = |identity, catalog, closed: &[SemanticId], token: &CancellationToken| {
        stage.insert_generated_bridge(
            &host,
            identity,
            assigned.lexical(),
            catalog,
            assigned.identities().lookup_recipes(),
            closed,
            token,
        )
    };
    let live = CancellationToken::new();
    let catalog = Some(assigned.identities());
    assert!(matches!(
        insert([1; 32], catalog, &[], &live).unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));
    let authority = selection.candidate_coverage_fingerprint();
    let changes = selection.connection().total_changes();
    assert!(matches!(
        insert([1; 32], catalog, &[], &live).unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));
    assert_eq!(
        selection.connection().total_changes(),
        changes,
        "exact reuse writes no rows"
    );
    assert!(
        insert([1; 32], None, &[], &live).is_err(),
        "catalog presence participates in descriptor"
    );
    assert!(
        insert([1; 32], catalog, &[SemanticId::context_local(29)], &live).is_err(),
        "closure participates in descriptor"
    );
    assert!(matches!(
        insert([1; 32], catalog, &[], &live).unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));

    assert_eq!(selection.candidate_coverage_fingerprint(), authority);
    let token = CancellationToken::new();
    let callback_token = token.clone();
    selection
        .connection()
        .create_scalar_function(
            "cancel_bridge_insert",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8,
            move |_| {
                callback_token.cancel();
                Ok(0)
            },
        )
        .unwrap();
    selection.with_owned_temp_write(|connection| {
        connection.execute_batch("CREATE TEMP TRIGGER cancel_bridge_after_insert AFTER INSERT ON selected_resolution_stage_producers BEGIN SELECT cancel_bridge_insert(); END;")?;
        Ok(())
    }).unwrap();
    assert!(matches!(
        insert([2; 32], catalog, &[], &token).unwrap(),
        SelectedResolutionStageOutcome::Cancelled
    ));
    assert!(
        token.is_cancelled(),
        "actual producer INSERT executed the cancellation trigger"
    );
    assert!(selection.connection().is_autocommit());
    assert_eq!(selection.candidate_coverage_fingerprint(), authority);
    assert_eq!(
        selection
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_producers",
                [],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
        1
    );
    // Cleanup is deliberately independent of the cancelled token.
    selection
        .with_owned_temp_write(|connection| {
            connection.execute_batch("DROP TRIGGER temp.cancel_bridge_after_insert")?;
            Ok(())
        })
        .unwrap();
    selection
        .connection()
        .remove_function("cancel_bridge_insert", 0)
        .unwrap();
    assert_eq!(selection.connection().query_row(
        "WITH RECURSIVE n(value) AS (VALUES(1) UNION ALL SELECT value+1 FROM n WHERE value<10000) SELECT sum(value) FROM n",
        [],|row|row.get::<_,i64>(0),
    ).unwrap(),50005000,"cancelled projection removed its SQL handler");
    stage.clear_facts().unwrap();
    assert!(matches!(
        insert([2; 32], catalog, &[], &live).unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));
    assert_eq!(selection.mounts().unwrap().len(), 1);
}

#[test]
fn ordinary_identity_lookup_preserves_late_shared_alias() {
    use crate::analyzer::resolution::{
        ResolutionSemanticIdentity, SharedNameId, SharedNameInterner,
    };
    use crate::analyzer::store::resolution::{SharedNameCache, SharedNameTable};
    use crate::analyzer::store::resolution_authority::SelectedResolutionAuthority;

    let fixture = SelectionFixture::custom_source(1, "class Model { void run() { run(); } }");
    let selection = fixture.open_ready(&[]);
    let host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let (stored, digest): (i64, [u8; 32]) = selection.connection().query_row(
        "SELECT catalog.shared_identity,identity.identity_digest FROM resolution_semantic_catalog catalog JOIN resolution_identities identity ON identity.id=catalog.shared_identity WHERE catalog.blob_id=?1 LIMIT 1",
        [host.blob_id()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    let before_publication = rusqlite::Connection::open_in_memory().unwrap();
    before_publication.execute_batch(
        "CREATE TABLE resolution_identities(id INTEGER PRIMARY KEY,identity_digest BLOB NOT NULL UNIQUE)",
    ).unwrap();
    let names = SharedNameTable::new(SharedNameCache::new());
    let request = names.interner(&before_publication).intern(digest);
    assert!(!request.is_interned());
    let authority = SelectedResolutionAuthority::new(
        selection.connection(),
        &names,
        selection.requested_mount_rows(),
        selection.persisted_mount_count(),
        selection.authority_validations(),
    );
    let live = CancellationToken::new();
    let identity = ResolutionSemanticIdentity::shared(request);
    assert_eq!(
        authority
            .semantic_for_identity(&host, identity, &live)
            .unwrap(),
        Some(None)
    );
    assert!(names.admit_persisted_names(&[(digest, SharedNameId::interned(stored))], &live));
    assert_eq!(
        authority
            .semantic_for_identity(&host, identity, &live)
            .unwrap(),
        Some(Some(SemanticId::shared_name(request)))
    );
}

#[test]
fn unsited_stage_reference_uses_payload_and_selected_owner() {
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let reference = SemanticId::operation_local(9001);
    let node = BindingNodeId::operation_local(9002);
    let fragment = BindingFragmentId::at_ordinal(0);
    let lowered = LoweredResolutionFragment::selected_macro_head_bridge(
        fragment,
        reference,
        node,
        BindingNodeId::operation_local(9003),
        PartialPathId::operation_local(9004),
    );
    assert!(lowered.semantics().is_empty());
    let live = CancellationToken::new();
    let stage = SelectedResolutionStage::new(&selection);
    let empty_authority = selection.candidate_coverage_fingerprint();
    let other_request = fixture.open_ready(&[]);
    assert_eq!(selection.fingerprint(), other_request.fingerprint());
    assert_ne!(
        empty_authority,
        other_request.candidate_coverage_fingerprint()
    );
    drop(other_request);
    assert!(matches!(
        stage
            .insert_generated_bridge(&host, [71; 32], &lowered, None, &[], &[], &live,)
            .unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));
    assert_ne!(selection.candidate_coverage_fingerprint(), empty_authority);
    assert_eq!(
        lexical::reference_nodes(
            &selection,
            &[
                (host.ordinal(), reference),
                (SelectedResolutionMountOrdinal::new(1), reference),
            ],
            &live
        )
        .unwrap(),
        Some(vec![Some(node), None])
    );
    // A second owner of the exact node must not multiply the keyed answer.
    assert!(matches!(
        stage
            .insert_generated_bridge(
                &host,
                [72; 32],
                &LoweredResolutionFragment::selected_macro_head_bridge(
                    fragment,
                    reference,
                    node,
                    BindingNodeId::operation_local(9003),
                    PartialPathId::operation_local(9005),
                ),
                None,
                &[],
                &[],
                &live,
            )
            .unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));
    assert_eq!(
        lexical::reference_nodes(&selection, &[(host.ordinal(), reference)], &live).unwrap(),
        Some(vec![Some(node)])
    );
    let before_clear = selection.candidate_coverage_fingerprint();
    selection.with_owned_temp_write(|connection| {
        connection.execute_batch("CREATE TEMP TRIGGER reject_stage_node_clear BEFORE DELETE ON selected_resolution_stage_nodes BEGIN SELECT RAISE(ABORT,'test atomic clear'); END;")?;
        Ok(())
    }).unwrap();
    assert!(stage.clear_facts().is_err());
    assert_eq!(selection.candidate_coverage_fingerprint(), before_clear);
    assert_eq!(
        selection
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_producers",
                [],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
        2
    );
    selection
        .with_owned_temp_write(|connection| {
            connection.execute_batch("DROP TRIGGER temp.reject_stage_node_clear")?;
            Ok(())
        })
        .unwrap();
    stage.clear_facts().unwrap();
    let cleared = selection.candidate_coverage_fingerprint();
    assert_ne!(cleared, before_clear);
    stage.clear_facts().unwrap();
    assert_eq!(selection.candidate_coverage_fingerprint(), cleared);
    assert_eq!(
        lexical::reference_nodes(&selection, &[(host.ordinal(), reference)], &live).unwrap(),
        Some(vec![None])
    );
}

#[test]
fn empty_producer_and_closed_reason_have_distinct_coverage_effects() {
    let fixture = SelectionFixture::new(1);
    let selection = fixture.open_ready(&[]);
    let host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let names = selection.shared_names();
    let empty = lower_resolution_facts_for_selection(
        BindingFragmentId::at_ordinal(0),
        &names,
        Language::Java,
        &FileResolutionFacts::default(),
    );
    let live = CancellationToken::new();
    let stage = SelectedResolutionStage::new(&selection);
    let insert = |identity, closed: &[SemanticId]| {
        stage
            .insert_generated_bridge(&host, identity, empty.lexical(), None, &[], closed, &live)
            .unwrap()
    };
    let before = selection.candidate_coverage_fingerprint();
    assert!(matches!(
        insert([81; 32], &[]),
        SelectedResolutionStageOutcome::Ready
    ));
    assert_eq!(selection.candidate_coverage_fingerprint(), before);
    stage.clear_facts().unwrap();
    assert_eq!(selection.candidate_coverage_fingerprint(), before);
    let closed = [SemanticId::context_local(812)];
    assert!(matches!(
        insert([82; 32], &closed),
        SelectedResolutionStageOutcome::Ready
    ));
    let after = selection.candidate_coverage_fingerprint();
    assert_ne!(after, before);
    assert!(matches!(
        insert([82; 32], &closed),
        SelectedResolutionStageOutcome::Ready
    ));
    assert_eq!(selection.candidate_coverage_fingerprint(), after);
    stage.clear_facts().unwrap();
    assert_ne!(selection.candidate_coverage_fingerprint(), after);
}

#[test]
fn authenticated_capsule_admission_replays_variables_and_rolls_back_cancelled_assignment() {
    use crate::analyzer::store::WorkspaceSnapshots;
    use crate::analyzer::store::resolution_operation::with_dense_selected_macro_fixture;
    use crate::analyzer::store::resolution_publication::{
        ResolutionContentPublicationOutcome, prepare_resolution_capsule,
    };
    use crate::analyzer::store::resolution_selection::{
        SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
    };

    with_dense_selected_macro_fixture(|store, owner, fixtures| {
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
        for (index, (fixture, first, repeat, changed, after_clear)) in cases.into_iter().enumerate()
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
                let ordinary = crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource::new_on_demand(&selection);
                for reason in ordinary
                    .unsupported_gap_reasons(
                        host.ordinal(),
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(site),
                        &live,
                    )
                    .unwrap()
                    .unwrap()
                {
                    expected_closed.insert(super::super::codec::encode_semantic(reason));
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
                        connection.execute_batch("DROP TRIGGER temp.cancel_capsule_projection")?;
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

#[test]
fn ordinary_candidate_identity_collision_is_rejected_before_stage_publication() {
    use crate::analyzer::resolution::{
        BatchResolutionFragmentSource, CandidatePathIdentity, PartialPath, ResolutionCompletion,
        ResolutionIncompleteReason,
    };
    use crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;
    let fixture = SelectionFixture::new(2);
    let selection = fixture.open_ready(&[]);
    let live = CancellationToken::new();
    let host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let local: u32 = selection.connection().query_row(
        "SELECT path.path FROM temp.selected_resolution_mounts mount JOIN main.resolution_paths path ON path.blob_id=mount.blob_id WHERE mount.mount_ordinal=0 ORDER BY path.path LIMIT 1", [], |row| row.get(0)).unwrap();
    let fragment = BindingFragmentId::at_ordinal(0);
    let id = PartialPathId::local(0, local);
    let candidate = CandidatePathIdentity::new(fragment, id);
    let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
    let mut hydrated = source.hydrate_candidate_paths(&[candidate], &live).unwrap();
    assert_eq!(hydrated.len(), 1);
    let original = hydrated.pop().unwrap().1;
    let changed = PartialPath::new(
        original.start().clone(),
        original.end().clone(),
        original.precedence().to_vec(),
        original.witness().to_vec(),
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
            SemanticId::context_local(123),
        )]),
    );
    assert_ne!(original, changed);
    let stage = SelectedResolutionStage::new(&selection);
    let before = selection.candidate_coverage_fingerprint();
    // Excluding the host from a reader does not withdraw ordinary authority.
    selection
        .with_owned_temp_write(|connection| {
            connection.execute(
                "DELETE FROM temp.selected_resolution_scope_mounts WHERE mount_ordinal=0",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    for (index, body) in [&original, &changed].into_iter().enumerate() {
        let lexical = LoweredResolutionFragment::new_for_test(
            fragment,
            Language::Java,
            Vec::new(),
            vec![(id, body.clone())],
        );
        assert!(
            stage
                .insert_generated_bridge(&host, [index as u8; 32], &lexical, None, &[], &[], &live)
                .is_err()
        );
        assert!(selection.connection().is_autocommit());
        assert_eq!(selection.candidate_coverage_fingerprint(), before);
        assert_eq!(
            selection
                .connection()
                .query_row(
                    "SELECT count(*) FROM temp.selected_resolution_stage_producers",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
    let cancel = CancellationToken::new();
    let trigger_cancel = cancel.clone();
    selection
        .connection()
        .create_scalar_function(
            "cancel_path_collision",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8,
            move |_| {
                trigger_cancel.cancel();
                Ok(0)
            },
        )
        .unwrap();
    selection.with_owned_temp_write(|connection| {
        connection.execute_batch("CREATE TEMP TRIGGER cancel_path_collision AFTER INSERT ON selected_resolution_stage_producers BEGIN SELECT cancel_path_collision(); END;")?;
        Ok(())
    }).unwrap();
    let lexical = LoweredResolutionFragment::new_for_test(
        fragment,
        Language::Java,
        Vec::new(),
        vec![(id, original.clone())],
    );
    assert!(matches!(
        stage
            .insert_generated_bridge(&host, [10; 32], &lexical, None, &[], &[], &cancel)
            .unwrap(),
        SelectedResolutionStageOutcome::Cancelled
    ));
    assert!(cancel.is_cancelled());
    assert_eq!(selection.candidate_coverage_fingerprint(), before);
    selection
        .with_owned_temp_write(|connection| {
            connection.execute_batch("DROP TRIGGER temp.cancel_path_collision")?;
            Ok(())
        })
        .unwrap();
    selection
        .connection()
        .remove_function("cancel_path_collision", 0)
        .unwrap();
    for (index, distinct) in [
        PartialPathId::operation_local(u64::from(local)),
        PartialPathId::context_local(u64::from(local)),
        PartialPathId::local(1, local),
    ]
    .into_iter()
    .enumerate()
    {
        let lexical = LoweredResolutionFragment::new_for_test(
            fragment,
            Language::Java,
            Vec::new(),
            vec![(distinct, original.clone())],
        );
        assert!(matches!(
            stage
                .insert_generated_bridge(
                    &host,
                    [20 + index as u8; 32],
                    &lexical,
                    None,
                    &[],
                    &[],
                    &live
                )
                .unwrap(),
            SelectedResolutionStageOutcome::Ready
        ));
    }
    assert_eq!(
        selection
            .connection()
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_stage_paths",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        3
    );
}

#[test]
fn capsule_membership_uses_active_producer_seek_under_both_statistics_states() {
    use crate::analyzer::store::planner_statistics::pinned_plans::{
        pinned, plan_rows, prepare_pin_context,
    };
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::{StatementStatus, types::Value};
    for noise in [16, 4096] {
        for statistics in PlannerStatisticsState::BOTH {
            let fixture = SelectionFixture::new(1);
            let writer = fixture.store.conn.lock().unwrap();
            let connection = &*writer;
            prepare_pin_context(connection);
            connection.execute("INSERT INTO temp.selected_resolution_mounts(mount_ordinal,blob_id,workspace_id,generation,revision,blob_oid,storage_language) VALUES(1,1,'owner',1,1,'host','rust'),(2,1,'foreign-owner',1,1,'host','rust'),(3,1,'owner',1,1,'foreign-host','rust')", []).unwrap();
            connection
                .execute("DELETE FROM temp.selected_resolution_admissions", [])
                .unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            for invocation in 0..=noise {
                transaction.execute("INSERT INTO temp.selected_resolution_admissions(workspace_id,storage_language,generation,revision,blob_id,blob_oid,manifest_digest,producer_epoch,logical_rows,payload_bytes,input_kind,host_content_oid,invocation,definition_content_oid,selected_declaration,matched_arm_index,derivation_digest,checkpoint_digest,host_module_scope) VALUES('owner','rust',1,1,1,?1,zeroblob(32),'epoch',1,0,1,'host',?2,'definition',0,0,zeroblob(32),zeroblob(32),0)",params![format!("capsule-{invocation}"),invocation]).unwrap();
                if invocation < noise {
                    transaction.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,admission_id) VALUES(1,?1)",[transaction.last_insert_rowid()]).unwrap();
                }
            }
            transaction.commit().unwrap();
            statistics.install(connection);
            for (host, invocation, want) in [
                (1, noise - 1, true),
                (1, noise, false),
                (1, noise + 1, false),
                (2, noise - 1, false),
                (3, noise - 1, false),
                (99, noise - 1, false),
            ] {
                let mut query = pinned("stage_capsule_membership");
                query.params = vec![Value::Integer(host), Value::Integer(invocation)];
                let plan = plan_rows(connection, &query).unwrap();
                assert!(
                    plan.iter()
                        .any(|line| line.contains("selected_resolution_admissions_invocation")),
                    "{statistics:?}: {plan:?}"
                );
                assert!(
                    plan.iter()
                        .any(|line| line.contains("selected_resolution_stage_capsule")),
                    "{statistics:?}: {plan:?}"
                );
                let mut statement = connection.prepare(&query.sql).unwrap();
                let actual: bool = statement
                    .query_row(rusqlite::params_from_iter(query.params.iter()), |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(actual, want);
                assert!(
                    statement.get_status(StatementStatus::VmStep) < 500,
                    "{statistics:?}: {plan:?}"
                );
            }
            connection
                .execute("DELETE FROM temp.selected_resolution_stage_producers", [])
                .unwrap();
            assert!(
                !connection
                    .query_row(CAPSULE_MEMBERSHIP_SQL, params![1, noise - 1], |row| row
                        .get::<_, bool>(0))
                    .unwrap()
            );
        }
    }
}

#[test]
fn ordinary_lookup_families_preserve_missing_and_late_shared_aliases() {
    use crate::analyzer::resolution::{SharedNameId, SharedNameInterner};
    use crate::analyzer::store::resolution::{SharedNameCache, SharedNameTable};
    use crate::analyzer::store::resolution_authority::SelectedResolutionAuthority;
    use crate::analyzer::store::resolution_prepare::authority_rows;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    let fixture = SelectionFixture::custom_rust_source(
        1,
        concat!(
            "mod model { pub struct Item; pub fn make() -> Item { Item } } ",
            "use crate::model::Item; ",
            "fn run(_: crate::model::Item) { let _: Item; let _ = model::make(); }",
        ),
    );
    let selection = fixture.open_ready(&[]);
    let host = selection
        .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
        .unwrap()
        .unwrap();
    let identities = selection
        .connection()
        .prepare("SELECT id,identity_digest FROM resolution_identities ORDER BY id")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, [u8; 32]>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    type Lookup = fn(
        &SelectedResolutionAuthority<'_>,
        &crate::analyzer::store::resolution_selection::SelectedResolutionMountRecord,
        SemanticId,
        &CancellationToken,
    ) -> crate::analyzer::store::Result<Option<Vec<ResolutionSiteId>>>;
    let families: [(&str, Lookup); 3] = [
        (
            authority_rows::LOOKUP_REFERENCE_SHARED_SQL,
            |reader, host, key, token| reader.lookup_reference_sites(host, key, None, token),
        ),
        (
            authority_rows::ROOT_DEMAND_SHARED_SQL,
            |reader, host, key, token| reader.root_demand_reference_sites(host, key, token),
        ),
        (
            authority_rows::QUALIFIED_ROUTE_REFERENCE_SITES_SQL,
            |reader, host, key, token| reader.qualified_route_reference_sites(host, key, token),
        ),
    ];
    let live = CancellationToken::new();
    for (sql, read) in families {
        let mut statement = selection.connection().prepare(sql).unwrap();
        let (stored, digest, expected) = identities
            .iter()
            .find_map(|&(stored, digest)| {
                let mut bindings = vec![
                    rusqlite::types::Value::Integer(host.blob_id()),
                    rusqlite::types::Value::Integer(stored),
                ];
                bindings.resize(statement.parameter_count(), rusqlite::types::Value::Null);
                let sites = statement
                    .query_map(rusqlite::params_from_iter(bindings), |row| {
                        row.get::<_, u32>(0)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                (!sites.is_empty()).then_some((
                    stored,
                    digest,
                    sites
                        .into_iter()
                        .map(ResolutionSiteId::new)
                        .collect::<Vec<_>>(),
                ))
            })
            .unwrap_or_else(|| panic!("actual parsed fixture must exercise lookup family: {sql}"));
        let before_publication = rusqlite::Connection::open_in_memory().unwrap();
        before_publication.execute_batch("CREATE TABLE resolution_identities(id INTEGER PRIMARY KEY,identity_digest BLOB NOT NULL UNIQUE)").unwrap();
        let names = SharedNameTable::new(SharedNameCache::new());
        let request = names.interner(&before_publication).intern(digest);
        assert!(!request.is_interned());
        let reader = SelectedResolutionAuthority::new(
            selection.connection(),
            &names,
            selection.requested_mount_rows(),
            selection.persisted_mount_count(),
            selection.authority_validations(),
        );
        let semantic = SemanticId::shared_name(request);
        assert_eq!(
            read(&reader, &host, semantic, &live).unwrap(),
            Some(Vec::new())
        );
        assert!(names.admit_persisted_names(&[(digest, SharedNameId::interned(stored))], &live));
        assert_eq!(
            read(&reader, &host, semantic, &live).unwrap(),
            Some(expected)
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(read(&reader, &host, semantic, &cancelled).unwrap(), None);
    }
}
