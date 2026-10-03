use super::super::coordinates::PreparedStageCoordinates;
use super::*;
use crate::analyzer::resolution::{
    PerRequestSharedNames, ResolutionIdentityCatalogBuilder, ResolutionNodeIdentity,
    ResolutionPathIdentity, ResolutionSemanticIdentity, ResolutionStackVariableIdentity,
};
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionTempTransaction, tests::SelectionFixture,
};

fn catalog() -> ResolutionIdentityCatalog {
    let names = PerRequestSharedNames::new();
    let mut builder =
        ResolutionIdentityCatalogBuilder::new(BindingFragmentId::at_ordinal(0), &names);
    builder.semantic(ResolutionSemanticIdentity::fragment_local([201; 32]));
    builder.shared_name([202; 32]);
    builder.node(ResolutionNodeIdentity::new([203; 32]));
    builder.path(ResolutionPathIdentity::new([204; 32]));
    builder.stack_variable(ResolutionStackVariableIdentity::new([205; 32]));
    builder.finish()
}

fn producer(connection: &Connection, host: u32, marker: u8) -> Result<i64> {
    connection.execute(
        "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
        params![host,[marker;32].as_slice(),[marker;32].as_slice()],
    )?;
    Ok(connection.last_insert_rowid())
}

fn counters(connection: &Connection) -> Vec<(u32, i64, i64)> {
    connection.prepare("SELECT host_ordinal,domain,next_key FROM temp.selected_resolution_stage_allocation_counters ORDER BY host_ordinal,domain").unwrap()
        .query_map([],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap()
        .collect::<rusqlite::Result<Vec<_>>>().unwrap()
}

#[test]
fn catalog_replay_preserves_variables_and_clear_preserves_high_water() {
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let host = SelectedResolutionMountOrdinal::new(0);
    let dense = catalog();
    let cancellation = CancellationToken::new();
    let (first_producer, first) = selection
        .with_owned_temp_transaction(|connection| {
            let assigned =
                assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
            let runtime = dense.clone().retargeted(&assigned);
            let producer = producer(connection, host.get(), 1)?;
            PreparedStageCoordinates::new(&runtime, &[], &cancellation)
                .unwrap()
                .insert(connection, producer, host)?;
            let before = counters(connection);
            let replay = replay_catalog(
                &selection,
                connection,
                producer,
                host,
                &dense,
                &cancellation,
            )?
            .unwrap();
            assert_eq!(dense.clone().retargeted(&replay), runtime);
            assert_eq!(
                counters(connection),
                before,
                "exact replay allocates nothing"
            );
            Ok(SelectedResolutionTempTransaction::Commit((
                producer, runtime,
            )))
        })
        .unwrap();
    selection
        .with_owned_temp_transaction(|connection| {
            let assigned =
                assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
            let second = dense.clone().retargeted(&assigned);
            assert_eq!(second.semantics(), first.semantics());
            assert_eq!(second.nodes(), first.nodes());
            assert_eq!(second.paths(), first.paths());
            assert_ne!(
                second.stack_variables(),
                first.stack_variables(),
                "new producer variables are fresh"
            );
            // Shared entries still consume one key on a new producer even on reuse.
            assert_eq!(
                counters(connection)
                    .iter()
                    .find(|row| row.1 == 0)
                    .unwrap()
                    .2,
                BASE + 3
            );
            let producer = producer(connection, host.get(), 2)?;
            PreparedStageCoordinates::new(&second, &[], &cancellation)
                .unwrap()
                .insert(connection, producer, host)?;
            let before = counters(connection);
            connection.execute("DELETE FROM temp.selected_resolution_stage_producers", [])?;
            assert_eq!(counters(connection), before);
            assert_eq!(
                connection.query_row(
                    "SELECT count(*) FROM temp.selected_resolution_stage_variable_coordinates",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            assert!(
                replay_catalog(
                    &selection,
                    connection,
                    first_producer,
                    host,
                    &dense,
                    &cancellation
                )
                .is_err()
            );
            let after =
                assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
            let after = dense.clone().retargeted(&after);
            assert!(after.nodes()[0].0.local_key() > first.nodes()[0].0.local_key());
            assert!(after.paths()[0].0.local_key() > first.paths()[0].0.local_key());
            assert!(
                after.stack_variables()[0].0.local_key()
                    > second.stack_variables()[0].0.local_key()
            );
            Ok(SelectedResolutionTempTransaction::Rollback(()))
        })
        .unwrap();
}

#[test]
fn ordered_reservations_match_scalar_policy_and_roll_back_overflow() {
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let host = SelectedResolutionMountOrdinal::new(1);
    let cancellation = CancellationToken::new();
    for domain in 0..4 {
        selection
            .with_owned_temp_transaction(|connection| {
                let reused =
                    |key| Some(i64::try_from(SemanticId::local(host.get(), key).get()).unwrap());
                // None at position two includes the shared-name counter burn.
                let inputs = [
                    None,
                    reused((BASE + 10) as u32),
                    None,
                    None,
                    reused(17),
                    None,
                ];
                let actual =
                    assign_keys(connection, host, domain, &inputs, &cancellation)?.unwrap();
                let mut next = BASE;
                let expected = inputs
                    .iter()
                    .map(|runtime| match runtime {
                        Some(runtime) => {
                            let key = runtime & i64::from(u32::MAX);
                            next = next.max(key + 1);
                            key as u32
                        }
                        None => {
                            let key = next;
                            next += 1;
                            key as u32
                        }
                    })
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected);
                assert_eq!(
                    actual,
                    vec![
                        BASE as u32,
                        (BASE + 10) as u32,
                        (BASE + 11) as u32,
                        (BASE + 12) as u32,
                        17,
                        (BASE + 13) as u32
                    ]
                );
                reserve(connection, host, domain, END - 1, 1)?;
                assert!(reserve(connection, host, domain, BASE, 1).is_err());
                assert_eq!(counters(connection), vec![(host.get(), domain, END)]);
                Ok(SelectedResolutionTempTransaction::Rollback(()))
            })
            .unwrap();
        assert!(counters(selection.connection()).is_empty());
    }
}

#[test]
fn cancellation_and_cross_host_failure_leave_no_reservations() {
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let dense = catalog();
    for budget in [0, 3, 12, 25] {
        selection
            .with_owned_temp_transaction(|connection| {
                let cancellation = CancellationToken::cancel_after_checks_for_test(budget);
                let outcome = assign_catalog(
                    &selection,
                    connection,
                    SelectedResolutionMountOrdinal::new(0),
                    &dense,
                    &cancellation,
                )?;
                assert!(outcome.is_none());
                Ok(SelectedResolutionTempTransaction::Rollback(()))
            })
            .unwrap();
        assert!(counters(selection.connection()).is_empty());
    }
    selection
        .with_owned_temp_transaction(|connection| {
            let cancellation = CancellationToken::new();
            for host in [0, 1] {
                let host = SelectedResolutionMountOrdinal::new(host);
                let assigned =
                    assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
                let runtime = dense.clone().retargeted(&assigned);
                let producer = producer(connection, host.get(), 3)?;
                PreparedStageCoordinates::new(&runtime, &[], &cancellation)
                    .unwrap()
                    .insert(connection, producer, host)?;
            }
            assert_eq!(counters(connection).len(), 8);
            Ok(SelectedResolutionTempTransaction::Rollback(()))
        })
        .unwrap();
    assert!(counters(selection.connection()).is_empty());
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

#[test]
fn ordinary_and_all_stage_owners_must_agree_independent_of_read_scope() {
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let host = SelectedResolutionMountOrdinal::new(1);
    selection.with_owned_temp_transaction(|connection| {
        let (key,digest):(u32,Vec<u8>)=connection.query_row("SELECT catalog.local_key,catalog.identity_digest FROM temp.selected_resolution_mounts mount JOIN main.resolution_node_catalog catalog ON catalog.blob_id=mount.blob_id WHERE mount.mount_ordinal=1 LIMIT 1",[],|row|Ok((row.get(0)?,row.get(1)?)))?;
        let identity = ResolutionNodeIdentity::new(digest.try_into().unwrap());
        let runtime = BindingNodeId::local(host.get(),key);
        connection.execute("DELETE FROM temp.selected_resolution_scope_mounts",[])?;
        assert_eq!(assign_node(&selection,connection,host,identity,&CancellationToken::new())?,Some(runtime));
        for marker in [4,5] {
            let producer = producer(connection,host.get(),marker)?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_node_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest) VALUES(?1,?2,0,?3,?4)",params![host.get(),producer,codec::encode_node(runtime),identity.digest().as_slice()])?;
        }
        assert_eq!(assign_node(&selection,connection,host,identity,&CancellationToken::new())?,Some(runtime));
        connection.execute("UPDATE temp.selected_resolution_stage_node_coordinates SET runtime_key=runtime_key+1 WHERE producer_id=(SELECT max(producer_id) FROM temp.selected_resolution_stage_producers)",[])?;
        assert!(assign_node(&selection,connection,host,identity,&CancellationToken::new()).is_err());
        Ok(SelectedResolutionTempTransaction::Rollback(()))
    }).unwrap();
}

#[test]
fn missing_or_changed_variable_correspondence_rejects_exact_replay() {
    let fixture = SelectionFixture::shared_blob(1);
    let selection = fixture.open_ready(&[]);
    let host = SelectedResolutionMountOrdinal::new(0);
    let dense = catalog();
    let cancellation = CancellationToken::new();
    selection.with_owned_temp_transaction(|connection| {
        let assigned = assign_catalog(&selection,connection,host,&dense,&cancellation)?.unwrap();
        let runtime = dense.clone().retargeted(&assigned);
        let producer = producer(connection,host.get(),6)?;
        PreparedStageCoordinates::new(&runtime, &[], &cancellation).unwrap().insert(connection,producer,host)?;
        connection.execute("UPDATE temp.selected_resolution_stage_variable_coordinates SET identity_digest=zeroblob(32) WHERE producer_id=?1",[producer])?;
        assert!(replay_catalog(&selection,connection,producer,host,&dense,&cancellation).is_err());
        connection.execute("DELETE FROM temp.selected_resolution_stage_variable_coordinates WHERE producer_id=?1",[producer])?;
        assert!(replay_catalog(&selection,connection,producer,host,&dense,&cancellation).is_err());
        Ok(SelectedResolutionTempTransaction::Rollback(()))
    }).unwrap();
}

#[test]
fn bundled_identity_seeks_use_existing_indexes_under_both_statistics_states() {
    use crate::analyzer::store::planner_statistics::pinned_plans::{
        pinned, plan_rows, prepare_pin_context,
    };
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::{StatementStatus, types::Value};
    let fixture = SelectionFixture::shared_blob(2);
    let writer = fixture.store.conn.lock().unwrap();
    let connection = &*writer;
    prepare_pin_context(connection);
    // Populate both ordinary authorities and stage namespaces with the same
    // digests. Shared requests must never pick the matching ordinary local ID.
    {
        let transaction = connection.unchecked_transaction().unwrap();
        let connection = &transaction;
        let producer = producer(connection, 1, 7).unwrap();
        let shared_producer = self::producer(connection, 1, 9).unwrap();
        let blob: i64 = connection
            .query_row(
                "SELECT blob_id FROM main.resolution_fragment_interiors LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO temp.selected_resolution_mounts(mount_ordinal,blob_id) VALUES(1,?1)",
                [blob],
            )
            .unwrap();
        for key in 0..4096_i64 {
            let mut digest = [0_u8; 32];
            digest[..8].copy_from_slice(&key.to_le_bytes());
            for table in ["semantic", "node"] {
                connection.execute(&format!("INSERT INTO main.resolution_{table}_catalog(blob_id,local_key,identity_digest) VALUES(?1,?2,?3)"), params![blob, 100000 + key, digest.as_slice()]).unwrap();
            }
            for table in ["semantic", "node", "path"] {
                connection.execute(&format!("INSERT INTO temp.selected_resolution_stage_{table}_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest) VALUES(1,?1,?2,?3,?4)"), params![producer,key,(1_i64<<32)+100000+key,digest.as_slice()]).unwrap();
            }
            connection.execute("INSERT INTO temp.selected_resolution_stage_semantic_coordinates(host_ordinal,producer_id,dense_key,shared_id,identity_digest) VALUES(1,?1,?2,?3,?4)", params![shared_producer,key,BASE+key,digest.as_slice()]).unwrap();
        }
        transaction.commit().unwrap();
    }
    for statistics in PlannerStatisticsState::BOTH {
        statistics.install(connection);
        for (family, table, spaces) in [
            ("semantics", "semantic", &[0, 1][..]),
            ("nodes", "node", &[0][..]),
            ("paths", "path", &[0][..]),
        ] {
            for &shared in spaces {
                for arity in [1, 64, 256] {
                    for hit in [true, false] {
                        let mut query =
                            pinned(&format!("stage_allocation_{family}_{shared}_{arity}"));
                        if !hit {
                            let request = (0..arity)
                                .map(|index| {
                                    let mut digest = [0_u8; 32];
                                    digest[..8]
                                        .copy_from_slice(&(index as i64 + 10000).to_le_bytes());
                                    json!([1, hex_digest(digest), shared])
                                })
                                .collect::<Vec<_>>();
                            query.params =
                                vec![Value::Text(serde_json::to_string(&request).unwrap())];
                        }
                        let plans = plan_rows(connection, &query).unwrap();
                        let stage_index = format!("selected_resolution_stage_{table}_identity");
                        assert!(
                            plans.iter().any(|line| line.contains("SEARCH staged")
                                && line.contains(&stage_index)),
                            "{statistics}: {}: {plans:?}",
                            query.name
                        );
                        if table != "path" {
                            assert!(
                                plans.iter().any(|line| line.contains("SEARCH ordinary")
                                    && line.contains("blob_id=? AND identity_digest=?")),
                                "{statistics}: {}: {plans:?}",
                                query.name
                            );
                        }
                        assert!(
                            !plans.iter().any(|line| line.contains("SCAN staged")
                                || line.contains("SCAN ordinary")
                                || line.contains("AUTOMATIC")
                                || line.contains("TEMP B-TREE")),
                            "{statistics}: {}: {plans:?}",
                            query.name
                        );
                        let mut statement = connection.prepare(&query.sql).unwrap();
                        let rows = statement
                            .query_map(rusqlite::params_from_iter(query.params.iter()), |row| {
                                Ok((
                                    row.get::<_, usize>(0)?,
                                    row.get::<_, Option<i64>>(1)?,
                                    row.get::<_, Option<i64>>(2)?,
                                    row.get::<_, Option<i64>>(3)?,
                                ))
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        assert_eq!(rows.len(), arity, "{statistics}: {}", query.name);
                        for (index, ordinary, runtime, name) in rows {
                            let local = (1_i64 << 32) + 100000 + index as i64;
                            assert_eq!(
                                ordinary,
                                (hit && shared == 0 && table != "path").then_some(local),
                                "{statistics}: {}",
                                query.name
                            );
                            assert_eq!(
                                runtime,
                                (hit && shared == 0).then_some(local),
                                "{statistics}: {}",
                                query.name
                            );
                            assert_eq!(
                                name,
                                (hit && shared == 1).then_some(BASE + index as i64),
                                "{statistics}: {}",
                                query.name
                            );
                        }
                        assert_eq!(
                            statement.get_status(StatementStatus::FullscanStep),
                            0,
                            "{statistics}: {}",
                            query.name
                        );
                        assert!(
                            statement.get_status(StatementStatus::VmStep)
                                < 100 * arity as i32 + 100,
                            "{statistics}: {}: {plans:?}",
                            query.name
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn same_digest_local_and_shared_semantics_keep_distinct_authorities() {
    let fixture = SelectionFixture::shared_blob(1);
    let selection = fixture.open_ready(&[]);
    let names = PerRequestSharedNames::new();
    let mut builder =
        ResolutionIdentityCatalogBuilder::new(BindingFragmentId::at_ordinal(0), &names);
    builder.semantic(ResolutionSemanticIdentity::fragment_local([210; 32]));
    builder.shared_name([210; 32]);
    let dense = builder.finish();
    let cancellation = CancellationToken::new();
    let host = SelectedResolutionMountOrdinal::new(0);
    selection
        .with_owned_temp_transaction(|connection| {
            let assigned =
                assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
            let first = dense.clone().retargeted(&assigned);
            let producer = producer(connection, 0, 8)?;
            PreparedStageCoordinates::new(&first, &[], &cancellation)
                .unwrap()
                .insert(connection, producer, host)?;
            let assigned =
                assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
            assert_eq!(dense.clone().retargeted(&assigned), first);
            assert_eq!(
                counters(connection)
                    .iter()
                    .find(|row| row.1 == 0)
                    .unwrap()
                    .2,
                BASE + 3
            );
            Ok(SelectedResolutionTempTransaction::Rollback(()))
        })
        .unwrap();
}

#[test]
fn late_persisted_shared_alias_reuses_request_identity_and_replays_both_owners() {
    use crate::analyzer::resolution::SharedNameId;
    let fixture = SelectionFixture::shared_blob(1);
    let selection = fixture.open_ready(&[]);
    let dense = catalog();
    let host = SelectedResolutionMountOrdinal::new(0);
    let cancellation = CancellationToken::new();
    let (first_producer, first) = selection
        .with_owned_temp_transaction(|connection| {
            let assigned =
                assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
            let runtime = dense.clone().retargeted(&assigned);
            let producer = producer(connection, 0, 10)?;
            PreparedStageCoordinates::new(&runtime, &[], &cancellation)
                .unwrap()
                .insert(connection, producer, host)?;
            Ok(SelectedResolutionTempTransaction::Commit((
                producer, runtime,
            )))
        })
        .unwrap();
    let request = first
        .semantics()
        .iter()
        .find_map(|(id, _)| id.shared_name_id())
        .unwrap();
    assert!(!request.is_interned());
    // Publish the immutable name after this request has already minted its ID.
    let stored = fixture.store.conn.execute(|connection| {
        connection
            .execute(
                "INSERT INTO main.resolution_identities(identity_digest) VALUES(?1)",
                [[202_u8; 32].as_slice()],
            )
            .unwrap();
        SharedNameId::interned(connection.last_insert_rowid())
    });
    let connection = selection.connection();
    assert_ne!(stored, request);
    assert!(
        selection
            .shared_name_table()
            .admit_persisted_names(&[([202; 32], stored)], &cancellation)
    );
    let names = selection.shared_name_table().interner(connection);
    assert_eq!(names.from_persisted(stored), request);
    assert_eq!(names.to_persisted(request), Some(stored));
    selection.with_owned_temp_transaction(|connection| {
        // One active owner carries the original request ID, another the newly
        // persisted alias. All-owner lookup must compare their canonical IDs.
        let second_producer = producer(connection, 0, 11)?;
        PreparedStageCoordinates::new(&first, &[], &cancellation).unwrap().insert(connection, second_producer, host)?;
        connection.execute("UPDATE temp.selected_resolution_stage_semantic_coordinates SET shared_id=?1 WHERE producer_id=?2 AND shared_id IS NOT NULL", params![stored.get(), second_producer])?;
        let before = counters(connection);
        for producer in [first_producer, second_producer] {
            let replay = replay_catalog(&selection, connection, producer, host, &dense, &cancellation)?.unwrap();
            assert_eq!(dense.clone().retargeted(&replay), first);
        }
        assert_eq!(counters(connection), before);
        let assigned = assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
        assert_eq!(dense.clone().retargeted(&assigned).semantics(), first.semantics());
        assert_eq!(counters(connection).iter().find(|row| row.1 == 0).unwrap().2, BASE + 3);
        Ok(SelectedResolutionTempTransaction::Rollback(()))
    }).unwrap();
}

#[test]
fn replay_rejects_extra_wrong_host_and_reordered_variable_rows() {
    let fixture = SelectionFixture::shared_blob(2);
    let selection = fixture.open_ready(&[]);
    let names = PerRequestSharedNames::new();
    let mut builder =
        ResolutionIdentityCatalogBuilder::new(BindingFragmentId::at_ordinal(0), &names);
    builder.stack_variable(ResolutionStackVariableIdentity::new([231; 32]));
    builder.stack_variable(ResolutionStackVariableIdentity::new([232; 32]));
    let dense = builder.finish();
    let host = SelectedResolutionMountOrdinal::new(0);
    let cancellation = CancellationToken::new();
    for corruption in [
        "INSERT INTO temp.selected_resolution_stage_variable_coordinates SELECT host_ordinal,producer_id,2,runtime_key+2,identity_digest FROM temp.selected_resolution_stage_variable_coordinates WHERE dense_key=0",
        "UPDATE temp.selected_resolution_stage_variable_coordinates SET host_ordinal=1 WHERE dense_key=0",
        "UPDATE temp.selected_resolution_stage_variable_coordinates SET runtime_key=runtime_key+4294967296 WHERE dense_key=0",
        "UPDATE temp.selected_resolution_stage_variable_coordinates SET dense_key=2 WHERE dense_key=1",
        "UPDATE temp.selected_resolution_stage_variable_coordinates SET dense_key=dense_key+2; UPDATE temp.selected_resolution_stage_variable_coordinates SET dense_key=3-dense_key",
    ] {
        selection
            .with_owned_temp_transaction(|connection| {
                let assigned =
                    assign_catalog(&selection, connection, host, &dense, &cancellation)?.unwrap();
                let runtime = dense.clone().retargeted(&assigned);
                let producer = producer(connection, 0, 12)?;
                PreparedStageCoordinates::new(&runtime, &[], &cancellation)
                    .unwrap()
                    .insert(connection, producer, host)?;
                let replay = replay_catalog(
                    &selection,
                    connection,
                    producer,
                    host,
                    &dense,
                    &cancellation,
                )?
                .unwrap();
                assert_eq!(dense.clone().retargeted(&replay), runtime);
                assert!(
                    replay_catalog(
                        &selection,
                        connection,
                        producer,
                        SelectedResolutionMountOrdinal::new(1),
                        &dense,
                        &cancellation
                    )
                    .is_err()
                );
                let before = counters(connection);
                connection.execute_batch(corruption)?;
                assert!(
                    replay_catalog(
                        &selection,
                        connection,
                        producer,
                        host,
                        &dense,
                        &cancellation
                    )
                    .is_err(),
                    "{corruption}"
                );
                assert_eq!(counters(connection), before);
                Ok(SelectedResolutionTempTransaction::Rollback(()))
            })
            .unwrap();
        assert!(counters(selection.connection()).is_empty());
    }
}
