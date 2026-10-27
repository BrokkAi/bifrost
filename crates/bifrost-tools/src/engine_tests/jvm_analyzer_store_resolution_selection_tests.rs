#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::CLEAR_SELECTED_RESOLUTION_TEMP_SQL;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::Language;

    use git2::Oid;

    use brokk_bifrost_analysis::analyzer::store::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;

    use brokk_bifrost_analysis::analyzer::store::resolution::ResolutionManifestCounts;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SELECTED_LANGUAGE_AUTHORITY_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SELECTED_MASK_BASE_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SELECTED_MASK_PAGE_CONTINUATION_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SELECTED_MASK_PAGE_INITIAL_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionContentMountRequest;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayAuthority;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionRevalidationOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionStale;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::StagedReadySelection;

    use rusqlite::types::Value;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::WORKSPACE_ID;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::tests::assert_plan_has_no_hazards;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::tests::assert_plan_order;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::tests::assert_workspace_snapshot_path_seek;

    use brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::tests::explain_plan;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::insert_selection_input;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::persist_selected_inventory;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::tests::required_plan_step;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selected_content_mount_status_sql;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selected_mount_status_sql;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selected_resolution_temp_schema_sql;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::validate_selection_input;

    use rusqlite::OptionalExtension;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId;

    #[track_caller]
    fn check_interior_count(
        ready: &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        expected: usize,
    ) {
        use brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection as begin,
            finish_production_selected_sql_trace_on_connection as finish,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_typed::SelectedResolutionTypedSource;
        begin(ready.connection());
        let cancellation = CancellationToken::default();
        assert!(
            SelectedResolutionLexicalSource::new_on_demand(ready)
                .validate_selected_interiors_for_test(&cancellation)
                .unwrap()
        );
        assert!(
            SelectedResolutionTypedSource::new_on_demand(ready)
                .validate_selected_interiors_for_test(&cancellation)
                .unwrap()
        );
        let cost = finish(ready.connection());
        assert_eq!(
            cost.statements
                .iter()
                .filter(|sql| sql.contains("SELECT COUNT(*), COUNT(interior.blob_id)"))
                .count(),
            expected,
            "{cost:?}"
        );
    }

    #[test]
    fn retained_interior_certificates_track_main_commits_and_temp_ddl() {
        use brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection as begin,
            finish_production_selected_sql_trace_on_connection as finish,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_typed::SelectedResolutionTypedSource;
        let mut fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        fixture.retain_one_reader();
        let schema;
        {
            let ready = fixture.open_ready(&[]);
            check_interior_count(&ready, 2);
            schema = ready
                .connection()
                .query_row("PRAGMA temp.schema_version", [], |row| row.get::<_, i64>(0))
                .unwrap();
        }
        let ready = fixture.open_ready(&[]);
        assert_eq!(
            ready
                .connection()
                .query_row("PRAGMA temp.schema_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            schema
        );
        check_interior_count(&ready, 0);
        let before_commit: i64 = ready
            .connection()
            .query_row("PRAGMA main.data_version", [], |row| row.get(0))
            .unwrap();
        fixture
            .store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE main.resolution_fragment_interiors SET payload_bytes=payload_bytes+1",
                [],
            )
            .unwrap();
        let after_commit: i64 = ready
            .connection()
            .query_row("PRAGMA main.data_version", [], |row| row.get(0))
            .unwrap();
        assert_ne!(before_commit, after_commit);
        check_interior_count(&ready, 2);
        ready
            .connection()
            .execute_batch("CREATE TEMP TABLE certificate_ddl_scratch(value INTEGER)")
            .unwrap();
        check_interior_count(&ready, 2);
        check_interior_count(&ready, 0);
        fixture
            .store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE main.resolution_fragment_interiors SET publication_state='building'",
                [],
            )
            .unwrap();
        begin(ready.connection());
        let error = SelectedResolutionLexicalSource::new_on_demand(&ready)
            .validate_selected_interiors_for_test(&CancellationToken::default())
            .unwrap_err();
        let cost = finish(ready.connection());
        assert!(
            error
                .to_string()
                .contains("selected resolution interior changed"),
            "{error}"
        );
        assert_eq!(
            cost.statements
                .iter()
                .filter(|sql| sql.contains("SELECT COUNT(*), COUNT(interior.blob_id)"))
                .count(),
            1,
            "{cost:?}"
        );
        assert!(
            SelectedResolutionTypedSource::new_on_demand(&ready)
                .validate_selected_interiors_for_test(&CancellationToken::default())
                .unwrap_err()
                .to_string()
                .contains("lost their exact complete interior")
        );
    }

    #[test]
    fn writable_fallback_always_checks_interiors_and_mount_writes_fail() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::with_store(
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
            1,
            "java",
            Language::Java,
            false,
            false,
            None,
        );
        for _ in 0..2 {
            let ready = fixture.open_ready(&[]);
            assert!(!ready.connection().is_readonly(rusqlite::MAIN_DB).unwrap());
            check_interior_count(&ready, 2);
            check_interior_count(&ready, 2);
            for sql in [
                "UPDATE temp.selected_resolution_mounts SET interior_digest=zeroblob(32)",
                "DELETE FROM temp.selected_resolution_mounts",
                "INSERT INTO temp.selected_resolution_mounts SELECT * FROM temp.selected_resolution_mounts",
            ] {
                let error = ready
                    .with_owned_temp_write(|conn| {
                        conn.execute(sql, [])?;
                        Ok(())
                    })
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("selected resolution mounts are immutable while retained"),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn selected_inventory_handles_zero_one_and_page_boundaries() {
        for count in [0, 1, 256, 257] {
            let fixture = crate::selection_fixture_support::JvmSelectionFixture::with_language(
                count,
                "java",
                Language::Java,
                true,
            );
            let ready = fixture.open_ready(&[]);
            assert_eq!(ready.workspace_id(), WORKSPACE_ID);
            assert!(ready.connection().is_autocommit());
            assert_eq!(ready.mounts().unwrap().len(), count);
            assert_eq!(
                ready.languages().unwrap()[0].expected_base_mount_count(),
                count
            );
            assert_eq!(
                ready
                    .mounts()
                    .unwrap()
                    .iter()
                    .map(|mount| mount.ordinal().get())
                    .collect::<Vec<_>>(),
                (0..u32::try_from(count).unwrap()).collect::<Vec<_>>()
            );
            assert!(ready.mounts().unwrap().windows(2).all(|pair| {
                pair[0].persisted_relative_path() < pair[1].persisted_relative_path()
            }));
            let rebaser = ready.mount_rebaser().borrow();
            for mount in ready.mounts().unwrap() {
                let registered = rebaser
                    .mount(mount.ordinal())
                    .expect("every validated persisted mount is registered");
                assert_eq!(registered.ordinal(), mount.ordinal());
                assert_eq!(registered.fragment(), mount.fragment_id());
            }
        }
    }
    #[test]
    fn selected_input_rows_preserve_canonical_order_and_overlay_authority() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(2);
        let cancellation = CancellationToken::default();
        let masks = [
            SelectedResolutionOverlayMask::removal("java", "src/0000.java"),
            SelectedResolutionOverlayMask::removal("java", "src/0001.java"),
        ];
        let mut content = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".into(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        for authority in [
            None,
            Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                content_digest: [1; 32],
            }),
            Some(SelectedResolutionOverlayAuthority::Counterfactual {
                base_content_digest: [1; 32],
            }),
            Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                content_digest: [2; 32],
            }),
        ] {
            content.overlay_authority = authority.clone();
            let key = validate_selection_input(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &masks,
                std::slice::from_ref(&content),
                &cancellation,
            )
            .unwrap()
            .unwrap();
            let conn = fixture.store.conn.lock().unwrap();
            ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute_batch(selected_resolution_temp_schema_sql())
                .unwrap();
            conn.execute_batch(CLEAR_SELECTED_RESOLUTION_TEMP_SQL)
                .unwrap();
            let tx = conn.unchecked_transaction().unwrap();
            assert!(
                insert_selection_input(
                    &tx,
                    &key.workspace_id,
                    &key.snapshots,
                    &key.languages,
                    &key.overlay_masks,
                    &key.content_mounts,
                    &cancellation
                )
                .unwrap()
            );
            tx.commit().unwrap();
            assert!(key.equals_selected_rows(&conn).unwrap());
            let reversed = [masks[1].clone(), masks[0].clone()];
            let reordered = validate_selection_input(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &reversed,
                std::slice::from_ref(&content),
                &cancellation,
            )
            .unwrap()
            .unwrap();
            assert_eq!(key, reordered);
            assert_eq!(key.routing_digest(), reordered.routing_digest());
            assert!(reordered.equals_selected_rows(&conn).unwrap());
            for other in [
                None,
                Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                    content_digest: [1; 32],
                }),
                Some(SelectedResolutionOverlayAuthority::Counterfactual {
                    base_content_digest: [1; 32],
                }),
                Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                    content_digest: [2; 32],
                }),
            ] {
                let mut changed = key.clone();
                changed.content_mounts[0].overlay_authority = other.clone();
                assert_eq!(
                    changed.equals_selected_rows(&conn).unwrap(),
                    other == authority
                );
            }
        }
    }
    #[test]
    fn selected_input_routing_collision_rebuilds_exact_relational_selection() {
        let (_temp, mut fixture) =
            crate::selection_fixture_support::JvmSelectionFixture::persistent(1);
        fixture.store.active_readers.capacity = 1;
        drop(fixture.open_ready(&[]));
        let mask = SelectedResolutionOverlayMask::removal("java", "src/0000.java");
        let key = validate_selection_input(
            &fixture.workspace_id,
            &fixture.snapshots,
            &[fixture.language()],
            std::slice::from_ref(&mask),
            &[],
            &CancellationToken::default(),
        )
        .unwrap()
        .unwrap();
        {
            let mut conn = fixture.store.active_read_conn().unwrap();
            let mut retained = conn.take_retained_resolution_selection().unwrap();
            retained.routing_digest = key.routing_digest();
            conn.put_retained_resolution_selection(retained);
        }
        let ready = fixture.open_ready(std::slice::from_ref(&mask));
        assert_eq!(
            ready.persisted_mount_count(),
            0,
            "a routing collision cannot return the old unmasked inventory"
        );
        assert!(key.equals_selected_rows(ready.connection()).unwrap());
    }
    #[test]
    fn selected_input_equality_query_failure_discards_unowned_temp_state() {
        let (_temp, mut fixture) =
            crate::selection_fixture_support::JvmSelectionFixture::persistent(1);
        fixture.store.active_readers.capacity = 1;
        drop(fixture.open_ready(&[]));
        {
            let mut conn = fixture.store.active_read_conn().unwrap();
            let retained = conn.take_retained_resolution_selection().unwrap();
            conn.execute_batch("DROP TABLE temp.selected_resolution_content_mounts")
                .unwrap();
            conn.put_retained_resolution_selection(retained);
        }
        let error = fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .err()
            .expect("missing key relation propagates its SQL failure");
        assert!(
            error
                .to_string()
                .contains("selected_resolution_content_mounts"),
            "{error}"
        );
        assert_eq!(
            fixture.open_ready(&[]).persisted_mount_count(),
            1,
            "a later reader rebuilds clean TEMP authority after the failed comparison"
        );
    }
    #[test]
    fn alternating_exact_selection_keys_retain_their_own_reader_and_temp_inventory() {
        let (_temp, fixture) = crate::selection_fixture_support::JvmSelectionFixture::persistent(2);
        let removal = SelectedResolutionOverlayMask::removal("java", "src/0000.java");
        for (masks, marker) in [(&[][..], -8193), (std::slice::from_ref(&removal), -8194)] {
            let ready = fixture.open_ready(masks);
            // A connection-local pragma identifies the reader without changing
            // its schema or data freshness stamp.
            ready
                .connection()
                .pragma_update(None, "cache_size", marker)
                .unwrap();
        }
        for _ in 0..4 {
            for (masks, marker, mounts) in [
                (&[][..], -8193, 2),
                (std::slice::from_ref(&removal), -8194, 1),
            ] {
                let ready = fixture.open_ready(masks);
                assert_eq!(ready.mounts().unwrap().len(), mounts);
                assert_eq!(
                    ready
                        .connection()
                        .pragma_query_value(None, "cache_size", |row| row.get::<_, i32>(0))
                        .unwrap(),
                    marker
                );
            }
        }
        let third = SelectedResolutionOverlayMask::removal("java", "src/0001.java");
        drop(fixture.open_ready(&[third]));
        let state = fixture.store.active_readers.state.lock().unwrap();
        assert_eq!(
            state
                .idle
                .iter()
                .filter(|reader| reader.resolution_selection.is_some())
                .count(),
            2
        );
    }
    #[test]
    fn concurrent_same_key_returns_keep_one_retained_reader() {
        let (_temp, fixture) = crate::selection_fixture_support::JvmSelectionFixture::persistent(1);
        let first = fixture.open_ready(&[]);
        let concurrent = fixture.open_ready(&[]);
        drop(first);
        drop(concurrent);
        let state = fixture.store.active_readers.state.lock().unwrap();
        assert_eq!(
            state
                .idle
                .iter()
                .filter(|reader| reader.resolution_selection.is_some())
                .count(),
            1
        );
    }
    #[test]
    fn external_store_change_invalidates_retained_materialization() {
        let (_temp, fixture) = crate::selection_fixture_support::JvmSelectionFixture::persistent(1);
        {
            let conn = fixture.store.active_read_conn().unwrap();
            ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute_batch(selected_resolution_temp_schema_sql())
                .unwrap();
            conn.execute_batch(
                "CREATE TEMP TABLE selection_materialization_probe(insertions INTEGER NOT NULL);
                 CREATE TEMP TRIGGER count_selected_resolution_materialization
                 AFTER INSERT ON selected_resolution_context
                 BEGIN
                   INSERT INTO selection_materialization_probe VALUES(1);
                 END;",
            )
            .unwrap();
        }
        drop(fixture.open_ready(&[]));
        fixture.store.conn.execute(|writer| {
            writer
                .execute_batch("CREATE TABLE retained_selection_invalidation_probe(value INTEGER)")
                .unwrap();
        });
        drop(fixture.open_ready(&[]));

        let conn = fixture.store.active_read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM temp.selection_materialization_probe",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            2,
            "a main-database commit must rebuild the selected TEMP state"
        );
    }
    #[test]
    fn cached_content_mount_lookup_seeks_published_rows_before_and_after_statistics() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(128);
        let request = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000080"),
            WorkspaceFileRow {
                rel_path: "src/0000.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000080").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let check = || {
            let outcome = fixture
                .store
                .open_selected_resolution_mount_inventory_with_content_mounts(
                    &fixture.workspace_id,
                    &fixture.snapshots,
                    &[fixture.language()],
                    &[SelectedResolutionOverlayMask::replacement(
                        "java",
                        "src/0000.java",
                    )],
                    std::slice::from_ref(&request),
                    &CancellationToken::default(),
                )
                .unwrap();
            let SelectedResolutionMountInventoryOutcome::Ready(ready) = outcome else {
                panic!("cached changed content must be available");
            };
            let plan = ready
                .connection()
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    selected_content_mount_status_sql()
                ))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for table in ["blobs", "meta", "interiors"] {
                assert!(
                    plan.iter()
                        .any(|detail| detail.starts_with(&format!("SEARCH {table} USING "))),
                    "{plan:?}"
                );
                assert!(
                    !plan
                        .iter()
                        .any(|detail| detail.starts_with(&format!("SCAN {table}"))),
                    "{plan:?}"
                );
            }
            assert_eq!(ready.mounts().unwrap().len(), 128);
            assert_eq!(
                ready.mounts().unwrap().last().unwrap().blob_oid(),
                request.blob_oid()
            );
        };
        check();
        fixture.store.refresh_planner_statistics().unwrap();
        check();
    }
    #[test]
    fn cached_content_mount_generation_is_authoritative() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        fixture
            .store
            .ensure_language_epoch_value("java", "content-witness-next-generation")
            .unwrap();
        let outcome = fixture
            .store
            .open_selected_resolution_mount_inventory_with_content_mounts(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[SelectedResolutionOverlayMask::replacement(
                    "java",
                    "src/cached.java",
                )],
                &[content_mount],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Stale(
                SelectedResolutionStale::AnalysisGeneration { .. }
            )
        ));
    }
    #[test]
    fn overlay_masks_handle_exact_and_overfull_pages_in_storage_order() {
        for count in [256, 257] {
            let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(0);
            let mut masks = (0..count)
                .rev()
                .map(|index| {
                    SelectedResolutionOverlayMask::replacement(
                        "java",
                        format!("generated/{index:04}.java"),
                    )
                })
                .collect::<Vec<_>>();
            let first = fixture.open_ready(&masks);
            assert_eq!(first.overlay_masks().unwrap().len(), count);
            assert_eq!(first.expected_transient_replacement_count(), count);
            assert!(first.mounts().unwrap().is_empty());
            assert!(first.overlay_masks().unwrap().windows(2).all(|pair| {
                pair[0].persisted_relative_path() < pair[1].persisted_relative_path()
            }));
            let expected_fingerprint = first.fingerprint();
            drop(first);

            masks.reverse();
            let reordered = fixture.open_ready(&masks);
            assert_eq!(reordered.fingerprint(), expected_fingerprint);
        }
    }
    #[test]
    fn mask_exclusion_precedes_persisted_artifact_availability() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        fixture.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
            conn.execute("UPDATE blob_meta SET is_complete = 0", [])
                .unwrap();
        });
        let ready = fixture.open_ready(&[SelectedResolutionOverlayMask::replacement(
            "java",
            "src/0000.java",
        )]);
        assert!(ready.mounts().unwrap().is_empty());
        assert!(ready.overlay_masks().unwrap()[0].masked_base().is_some());
        assert_eq!(ready.expected_transient_replacement_count(), 1);
    }
    #[test]
    fn all_masked_language_remains_distinct_from_empty_language() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let ready = fixture.open_ready(&[SelectedResolutionOverlayMask::removal(
            "java",
            "src/0000.java",
        )]);
        assert!(ready.mounts().unwrap().is_empty());
        assert_eq!(ready.languages().unwrap()[0].expected_base_mount_count(), 1);
        assert_eq!(ready.languages().unwrap()[0].masked_base_mount_count(), 1);
        assert_eq!(
            ready.languages().unwrap()[0].expected_unmasked_mount_count(),
            0
        );
        assert_eq!(ready.expected_transient_replacement_count(), 0);
    }
    #[test]
    fn exact_mount_identity_restores_across_a_b_a_revisions() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let first = fixture.open_ready(&[]).mounts().unwrap()[0].fragment_digest();
        let generation = fixture.snapshots["java"].generation;
        let workspace_id = fixture.workspace_id.as_str().to_owned();
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 2)",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_file_versions SET valid_until = 2
                 WHERE workspace_id = ?1 AND lang = 'java' AND valid_until IS NULL",
                [&workspace_id],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) SELECT ?1, 'java', ?2, 'src/0000.java', blob_oid,
                          ?3, 2
                   FROM workspace_file_versions
                  WHERE workspace_id = ?1 AND lang = 'java' AND valid_from = 1",
                params![workspace_id, generation.0, "b".repeat(64)],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_heads SET revision = 2
                 WHERE workspace_id = ?1 AND lang = 'java' AND generation = ?2",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let mut revision_two = fixture.snapshots.clone();
        revision_two.get_mut("java").unwrap().revision = 2;
        let second = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &revision_two,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => {
                ready.mounts().unwrap()[0].fragment_digest()
            }
            _ => panic!("revision B must be Ready"),
        };
        // Two revisions of one file are two contents at one mount ordinal, so
        // what separates them is the mount's content key. The ordinal is a
        // position in the selection and is the same in both.
        assert_ne!(first, second);

        let workspace_id = fixture.workspace_id.as_str().to_owned();
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 3)",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_file_versions SET valid_until = 3
                 WHERE workspace_id = ?1 AND lang = 'java' AND valid_from = 2",
                [&workspace_id],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) SELECT ?1, 'java', ?2, 'src/0000.java', blob_oid,
                          ?3, 3
                   FROM workspace_file_versions
                  WHERE workspace_id = ?1 AND lang = 'java' AND valid_from = 1",
                params![workspace_id, generation.0, format!("{:064x}", 1)],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_heads SET revision = 3
                 WHERE workspace_id = ?1 AND lang = 'java' AND generation = ?2",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let mut revision_three = fixture.snapshots.clone();
        revision_three.get_mut("java").unwrap().revision = 3;
        let restored = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &revision_three,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => {
                ready.mounts().unwrap()[0].fragment_digest()
            }
            _ => panic!("restored revision A must be Ready"),
        };
        assert_eq!(restored, first);

        let retained = fixture.open_ready(&[]);
        assert_eq!(retained.languages().unwrap()[0].revision(), 1);
        assert_eq!(retained.mounts().unwrap()[0].fragment_digest(), first);
    }
    #[test]
    fn overlapping_path_at_page_boundary_fails_closed() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::with_language(
            256,
            "java",
            Language::Java,
            true,
        );
        let generation = fixture.snapshots["java"].generation;
        let workspace_id = fixture.workspace_id.as_str().to_owned();
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 2)",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from, valid_until
                 ) SELECT ?1, 'java', ?2, rel_path, blob_oid,
                          projection_digest, 2, 3
                   FROM workspace_file_versions
                  WHERE workspace_id = ?1 AND lang = 'java'
                    AND rel_path = 'src/0255.java' AND valid_from = 1",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let mut overlapping = fixture.snapshots.clone();
        overlapping.get_mut("java").unwrap().revision = 2;
        let result = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &overlapping,
            &[fixture.language()],
            &[],
            &CancellationToken::default(),
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("overlapping selected path must fail closed"),
        };
        assert!(error.to_string().contains("overlapping file versions"));
    }
    #[test]
    fn read_change_stamp_observes_schema_external_and_same_connection_changes() {
        // The single-connection store retains the writable fallback; pooled
        // readers permit TEMP writes but intentionally reject main writes.
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::with_store(
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
            1,
            "java",
            Language::Java,
            false,
            false,
            None,
        );
        let ready = fixture.open_ready(&[]);
        let conn = ready.connection();
        let original = ready.read_change_stamp().unwrap();
        conn.execute_batch("CREATE TEMP TABLE validation_probe(value INTEGER)")
            .unwrap();
        let before_owned_schema = ready.read_change_stamp().unwrap();
        ready.ensure_generic_formals_schema(conn).unwrap();
        ready.ensure_generic_formal_defaults_schema(conn).unwrap();
        let temp_schema = ready.read_change_stamp().unwrap();
        assert_eq!(
            temp_schema, before_owned_schema,
            "owned DDL cannot hide earlier unowned schema drift"
        );
        assert_ne!(
            temp_schema.temp_schema_version,
            original.temp_schema_version
        );
        assert_eq!(
            temp_schema.main_schema_version,
            original.main_schema_version
        );
        conn.execute_batch("CREATE TABLE main.validation_probe(value INTEGER)")
            .unwrap();
        let main_schema = ready.read_change_stamp().unwrap();
        assert_ne!(
            main_schema.main_schema_version,
            temp_schema.main_schema_version
        );
        assert_eq!(
            main_schema.temp_schema_version,
            temp_schema.temp_schema_version
        );
        conn.execute("INSERT INTO main.validation_probe VALUES(1)", [])
            .unwrap();
        let same_connection = ready.read_change_stamp().unwrap();
        assert_eq!(
            same_connection.main_data_version,
            main_schema.main_data_version
        );
        assert_eq!(
            same_connection.unowned_changes,
            main_schema.unowned_changes + 1
        );
        conn.execute_batch("VACUUM").unwrap();
        let vacuumed = ready.read_change_stamp().unwrap();
        assert_eq!(vacuumed.unowned_changes, same_connection.unowned_changes);
        assert_ne!(
            vacuumed.main_schema_version,
            same_connection.main_schema_version
        );

        let (_temp, persistent) =
            crate::selection_fixture_support::JvmSelectionFixture::persistent(1);
        persistent.store.conn.execute(|writer| {
            writer
                .execute_batch("CREATE TABLE main.validation_probe(value INTEGER)")
                .unwrap();
        });
        let pooled = persistent.open_ready(&[]);
        let before_external = pooled.read_change_stamp().unwrap();
        persistent.store.conn.execute(|writer| {
            writer
                .execute("INSERT INTO main.validation_probe VALUES(2)", [])
                .unwrap();
        });
        let external = pooled.read_change_stamp().unwrap();
        assert_ne!(
            external.main_data_version,
            before_external.main_data_version
        );
        assert_eq!(
            external.main_schema_version,
            before_external.main_schema_version
        );
        assert_eq!(external.unowned_changes, before_external.unowned_changes);
    }
    #[test]
    fn cancellation_is_terminal_before_input_and_during_paged_materialization() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::with_language(
            257,
            "java",
            Language::Java,
            true,
        );
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &fixture.workspace_id,
                    &WorkspaceSnapshots::default(),
                    &[fixture.language()],
                    &[],
                    &cancelled,
                )
                .unwrap(),
            SelectedResolutionMountInventoryOutcome::Cancelled
        ));

        let writer_fixture = crate::selection_fixture_support::JvmSelectionFixture::with_store(
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
            257,
            "java",
            Language::Java,
            true,
            false,
            None,
        );
        let writer_cancelled = CancellationToken::cancel_after_checks_for_test(400);
        assert!(matches!(
            writer_fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &writer_fixture.workspace_id,
                    &writer_fixture.snapshots,
                    &[writer_fixture.language()],
                    &[],
                    &writer_cancelled,
                )
                .unwrap(),
            SelectedResolutionMountInventoryOutcome::Cancelled
        ));
        drop(writer_fixture.open_ready(&[]));

        let mid_read = CancellationToken::cancel_after_checks_for_test(400);
        assert!(matches!(
            fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &fixture.workspace_id,
                    &fixture.snapshots,
                    &[fixture.language()],
                    &[],
                    &mid_read,
                )
                .unwrap(),
            SelectedResolutionMountInventoryOutcome::Cancelled
        ));
    }
    #[test]
    fn reused_inventory_validation_still_observes_later_epoch_drift() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let mut ready = fixture.open_ready(&[]);
        ready
            .with_owned_temp_write(|connection| {
                connection.execute_batch(
                    "CREATE TEMP TABLE inventory_validation_scratch(value INTEGER)",
                )?;
                Ok(())
            })
            .unwrap();
        let cancellation = CancellationToken::default();
        for _ in 0..2 {
            assert!(matches!(
                ready.revalidate(&cancellation).unwrap(),
                SelectedResolutionRevalidationOutcome::Current
            ));
        }
        fixture.store.conn.execute(|conn| {
            conn.execute(
                "UPDATE resolution_producer_epochs SET producer_epoch = 'future' WHERE lang = 'java'",
                [],
            )
            .unwrap();
        });
        assert!(matches!(
            ready.revalidate(&cancellation).unwrap(),
            SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::ProducerEpoch { .. }
            )
        ));
    }
    #[test]
    fn post_ready_epoch_drift_revalidates_stale() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let mut ready = fixture.open_ready(&[]);
        fixture.store.conn.execute(|conn| {
            conn.execute(
                "UPDATE resolution_producer_epochs SET producer_epoch = 'future'
                 WHERE lang = 'java'",
                [],
            )
            .unwrap();
        });
        assert!(matches!(
            ready.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::ProducerEpoch { .. }
            )
        ));
    }
    #[test]
    fn post_ready_membership_or_artifact_loss_is_inventory_drift() {
        let membership = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let mut ready = membership.open_ready(&[]);
        membership.store.conn.execute(|conn| {
            conn.execute("DELETE FROM workspace_file_versions", [])
                .unwrap();
        });
        assert!(matches!(
            ready.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::MountInventoryChanged
            )
        ));
        drop(ready);

        let artifact = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let mut ready = artifact.open_ready(&[]);
        artifact.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
        });
        assert!(matches!(
            ready.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::MountInventoryChanged
            )
        ));
    }
    #[test]
    fn interrupted_stage_dml_rolls_back_and_releases_reader_cancellation() {
        use brokk_bifrost_analysis::analyzer::store::resolution::with_resolution_read_progress_handler;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        let cancellation = CancellationToken::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let callback_token = cancellation.clone();
        ready
            .connection()
            .create_scalar_function(
                "cancel_stage_dml",
                1,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |context| {
                    if callback_calls.fetch_add(1, Ordering::Relaxed) + 1 == 128 {
                        callback_token.cancel();
                    }
                    context.get::<i64>(0)
                },
            )
            .unwrap();
        let scope_before: i64 = ready
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM temp.selected_resolution_scope_mounts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let committed_before = ready.retained().committed_request_changes.get();
        let cancelled = ready.with_owned_temp_transaction(|connection| {
            ready.ensure_generic_formals_schema(connection)?;
            let interrupted = with_resolution_read_progress_handler(connection, &cancellation, |connection| {
                // Admission validation nests a handler on this same connection.
                // Its removal must leave the outer DML cancellation active.
                with_resolution_read_progress_handler(connection, &cancellation, |connection| {
                    let value: i64 = connection.query_row("SELECT 7", [], |row| row.get(0))?;
                    assert_eq!(value, 7);
                    Ok(())
                })?;
                connection.execute(
                    "WITH RECURSIVE generated(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM generated WHERE n<100000) INSERT INTO temp.selected_resolution_scope_mounts(mount_ordinal) SELECT cancel_stage_dml(n) FROM generated",
                    [],
                )?;
                Ok(())
            }).expect_err("the SQL callback cancels during actual DML");
            assert!(interrupted.is_sqlite_interrupted());
            assert!(connection.is_autocommit(), "SQLite interrupt rolls back the transaction");
            Ok(SelectedResolutionTempTransaction::Rollback(true))
        }).unwrap();
        assert!(cancelled);
        let schema_survived: bool = ready.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE name='selected_resolution_stage_generic_formals')",
            [], |row| row.get(0),
        ).unwrap();
        assert!(
            !schema_survived,
            "cancellation rolls back the owned schema batch"
        );
        assert!(
            !ready.retained().is_current(ready.connection()).unwrap(),
            "rolled-back schema setup cannot authorize retention"
        );

        assert!((128..100000).contains(&calls.load(Ordering::Relaxed)));
        assert_eq!(
            ready.retained().committed_request_changes.get(),
            committed_before
        );
        assert!(ready.connection().is_autocommit());
        let count: i64 = ready
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM temp.selected_resolution_scope_mounts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, scope_before);
        // This exceeds the progress quantum while the original token remains
        // cancelled; a leaked handler would interrupt it.
        let sum: i64 = ready.connection().query_row(
            "WITH RECURSIVE generated(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM generated WHERE n<10000) SELECT sum(n) FROM generated", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(sum, 50_005_000);
        ready
            .connection()
            .remove_function("cancel_stage_dml", 1)
            .unwrap();
        assert_eq!(ready.mounts().unwrap().len(), 1);
        drop(ready);
        let reused = fixture.open_ready(&[]);
        assert_eq!(reused.mounts().unwrap().len(), 1);
        assert!(reused.connection().is_autocommit());
    }
    #[test]
    fn temp_state_clears_before_active_reader_reuse() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        ready
            .connection()
            .execute(
                "INSERT INTO temp.selected_resolution_scope_mounts(mount_ordinal) VALUES(7)",
                [],
            )
            .unwrap();
        drop(ready);
        let conn = fixture.store.active_read_conn().unwrap();
        for table in [
            "selected_resolution_context",
            "selected_resolution_languages",
            "selected_resolution_overlay_masks",
            "selected_resolution_content_mounts",
            "selected_resolution_mounts",
            "selected_rust_transient_placement_attributes",
            "selected_resolution_transient_placements",
            "selected_resolution_scope_mounts",
            "selected_workspace_revisions",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM temp.{table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} leaked through the active-reader pool");
        }
    }
    #[test]
    fn selected_mount_blob_index_is_recreated_and_survives_retained_state() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        ready
            .connection()
            .execute_batch("DROP INDEX temp.selected_resolution_mounts_blob_ordinal")
            .unwrap();
        assert_eq!(
            ready
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM temp.sqlite_schema
                     WHERE type = 'index'
                       AND name = 'selected_resolution_mounts_blob_ordinal'",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
            0
        );
        drop(ready);

        let ready = fixture.open_ready(&[]);
        assert_eq!(
            ready
                .connection()
                .prepare(
                    "SELECT name
                     FROM pragma_index_info('selected_resolution_mounts_blob_ordinal')
                     ORDER BY seqno",
                )
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap(),
            ["blob_id", "mount_ordinal"].map(str::to_owned),
            "opening a Ready selection must restore the exact TEMP covering index"
        );
        drop(ready);

        let conn = fixture.store.active_read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM temp.selected_resolution_mounts",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            1,
            "the rebuilt Ready selection must retain its exact TEMP mount row"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM temp.sqlite_schema
                 WHERE type = 'index'
                   AND name = 'selected_resolution_mounts_blob_ordinal'",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            1
        );
    }
    #[test]
    fn simultaneous_ready_sessions_keep_connection_local_workspace_state() {
        let (_temp, fixture) = crate::selection_fixture_support::JvmSelectionFixture::persistent(1);
        let other_workspace =
            WorkspaceId("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        let other_workspace_text = other_workspace.as_str().to_owned();
        let generation = fixture.snapshots["java"].generation;
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 1)",
                params![other_workspace_text, generation.0],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 1)",
                params![other_workspace_text, generation.0],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) SELECT ?1, 'java', ?2, 'src/0000.java', blob_oid, ?3, 1
                     FROM blobs WHERE lang = 'java' LIMIT 1",
                params![other_workspace_text, generation.0, format!("{:064x}", 1)],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let other_snapshots = WorkspaceSnapshots::from_iter([(
            "java".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: other_workspace.clone(),
                lang: "java".to_owned(),
                generation,
                revision: 1,
            },
        )]);

        let mut first = fixture.open_ready(&[]);
        let mut second = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &other_workspace,
                &other_snapshots,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            _ => panic!("second exact workspace selection must be Ready"),
        };
        assert_eq!(first.workspace_id(), WORKSPACE_ID);
        assert_eq!(
            first.mounts().unwrap()[0].persisted_relative_path(),
            "src/0000.java"
        );
        assert_eq!(second.workspace_id(), other_workspace.as_str());
        assert_eq!(
            second.mounts().unwrap()[0].persisted_relative_path(),
            "src/0000.java"
        );
        // A runtime fragment is its mount's ordinal, and each selection
        // numbers its own mounts from zero, so two sessions' first mounts
        // share a fragment id and are told apart by what they mount: these
        // two name different content in different workspaces.
        assert_eq!(
            first.mounts().unwrap()[0].fragment_id(),
            second.mounts().unwrap()[0].fragment_id()
        );
        assert_ne!(
            first.mounts().unwrap()[0].fragment_digest(),
            second.mounts().unwrap()[0].fragment_digest()
        );
        assert!(!std::ptr::eq(first.connection(), second.connection()));
        for (ready, expected) in [
            (&first, fixture.workspace_id.as_str()),
            (&second, other_workspace.as_str()),
        ] {
            assert_eq!(
                ready
                    .connection()
                    .query_row(
                        "SELECT workspace_id FROM temp.selected_resolution_context",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                expected
            );
        }
        assert_eq!(
            first.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
        assert_eq!(
            second.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
        drop(first);
        drop(second);

        let first_conn = fixture.store.active_read_conn().unwrap();
        let second_conn = fixture.store.active_read_conn().unwrap();
        assert!(!std::ptr::eq(&*first_conn, &*second_conn));
        for conn in [&*first_conn, &*second_conn] {
            for (table, expected) in [
                ("selected_resolution_context", 1),
                ("selected_resolution_languages", 1),
                ("selected_resolution_overlay_masks", 0),
                ("selected_resolution_content_mounts", 0),
                ("selected_resolution_mounts", 1),
                ("selected_resolution_scope_mounts", 1),
                ("selected_workspace_revisions", 1),
            ] {
                assert_eq!(
                    conn.query_row(&format!("SELECT COUNT(*) FROM temp.{table}"), [], |row| row
                        .get::<_, usize>(0),)
                        .unwrap(),
                    expected,
                    "{table} must retain exactly one connection-local selection"
                );
            }
        }
    }
    #[test]
    fn selected_query_plans_restore_the_pooled_readers_previous_setting() {
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        for previous in [false, true] {
            {
                let conn = fixture.store.active_read_conn().unwrap();
                conn.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, previous)
                    .unwrap();
                conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS planner_reuse_marker(x)")
                    .unwrap();
            }
            for unwind in [false, true] {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let ready = fixture.open_ready(&[]);
                    assert!(
                        ready
                            .connection()
                            .db_config(SQLITE_DBCONFIG_ENABLE_QPSG)
                            .unwrap()
                    );
                    assert!(!unwind, "exercise selected-reader unwinding");
                }));
                assert_eq!(result.is_err(), unwind);
                let conn = fixture.store.active_read_conn().unwrap();
                assert_eq!(
                    conn.db_config(SQLITE_DBCONFIG_ENABLE_QPSG).unwrap(),
                    previous,
                    "selected planner configuration leaked after unwind={unwind}"
                );
                assert_eq!(
                    conn.query_row(
                        "SELECT COUNT(*) FROM temp.planner_reuse_marker",
                        [],
                        |row| { row.get::<_, usize>(0) }
                    )
                    .unwrap(),
                    0,
                    "the same cleaned reader must remain reusable"
                );
            }
        }
    }
    #[test]
    fn retained_selection_checkout_preserves_prepared_query_plans() {
        use rusqlite::StatementStatus;
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        let mut fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        fixture.retain_one_reader();
        for run in 1..=3 {
            let ready = fixture.open_ready(&[]);
            let mut statement = ready
                .connection()
                .prepare_cached(
                    "SELECT workspace_id FROM temp.selected_resolution_context /* plan lifetime */",
                )
                .unwrap();
            let workspace: String = statement.query_row([], |row| row.get(0)).unwrap();
            assert_eq!(workspace, fixture.workspace_id.as_str());
            assert_eq!(statement.get_status(StatementStatus::Run), run);
            assert_eq!(
                statement.get_status(StatementStatus::RePrepare),
                0,
                "unchanged retained selection must reuse its compiled plan at run {run}"
            );
        }
        // An ordinary borrower must receive its original planner policy,
        // even when its pooled connection previously served resolution.
        let ordinary = fixture.store.active_read_conn().unwrap();
        assert!(!ordinary.db_config(SQLITE_DBCONFIG_ENABLE_QPSG).unwrap());
    }
    #[test]
    fn cleanup_failure_discards_pooled_reader_and_writer_fallback_fails_stop() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        ready
            .connection()
            .execute_batch("DROP TABLE temp.selected_resolution_mounts")
            .unwrap();
        assert_eq!(
            ready
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM temp.sqlite_schema
                     WHERE type = 'index'
                       AND name = 'selected_resolution_mounts_blob_ordinal'",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
            0,
            "dropping the TEMP mount table must also remove its connection-local index"
        );
        drop(ready);
        let conn = fixture.store.active_read_conn().unwrap();
        let table_exists = conn
            .query_row(
                "SELECT 1 FROM temp.sqlite_schema
                 WHERE type = 'table' AND name = 'selected_resolution_context'",
                [],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some();
        assert!(!table_exists, "failed cleanup connection returned to pool");
        drop(conn);

        let fallback = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let mut conn = fallback.active_read_conn().unwrap();
            conn.discard_before_checkin();
        }));
        assert!(
            panic.is_err(),
            "writer fallback must fail-stop on contamination"
        );
    }
    #[test]
    fn selected_queries_are_context_first_keyed_and_sort_free() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::with_language(
            257,
            "java",
            Language::Java,
            true,
        );
        let mut masks = (0..256)
            .map(|index| {
                SelectedResolutionOverlayMask::replacement("java", format!("src/{index:04}.java"))
            })
            .collect::<Vec<_>>();
        masks.push(SelectedResolutionOverlayMask::replacement(
            "java",
            "generated/New.java",
        ));
        let ready = fixture.open_ready(&masks);
        assert_eq!(ready.overlay_masks().unwrap().len(), 257);
        assert_eq!(ready.mounts().unwrap().len(), 1);

        let mount_index_columns = ready
            .connection()
            .prepare(
                "SELECT name
                 FROM pragma_index_info('selected_resolution_mounts_blob_ordinal')
                 ORDER BY seqno",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            mount_index_columns,
            ["blob_id", "mount_ordinal"].map(str::to_owned),
            "the selected root lookup index must retain its exact covering order"
        );

        let root_membership = explain_plan(
            ready.connection(),
            "SELECT mount_ordinal
             FROM temp.selected_resolution_mounts AS mounts
             WHERE blob_id = ?1
             ORDER BY mount_ordinal",
            vec![Value::Integer(ready.mounts().unwrap()[0].blob_id())],
        );
        required_plan_step(
            &root_membership,
            "selected root blob membership",
            &[
                "SEARCH mounts",
                "COVERING INDEX selected_resolution_mounts_blob_ordinal",
                "blob_id=?",
            ],
        );
        assert_plan_has_no_hazards(
            &root_membership,
            "selected root blob membership",
            &["mounts"],
        );

        let authority = explain_plan(ready.connection(), SELECTED_LANGUAGE_AUTHORITY_SQL, vec![]);
        assert_plan_order(
            &authority,
            "selected language authority",
            &[
                ("language input", &["SCAN languages"]),
                (
                    "selected revision",
                    &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "revision authority",
                    &[
                        "SEARCH revisions",
                        "PRIMARY KEY",
                        "workspace_id=?",
                        "lang=?",
                        "generation=?",
                        "revision=?",
                    ],
                ),
                (
                    "generation authority",
                    &["SEARCH epochs", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "producer authority",
                    &["SEARCH active", "PRIMARY KEY", "lang=?"],
                ),
            ],
        );
        assert_plan_has_no_hazards(
            &authority,
            "selected language authority",
            &["selected", "revisions", "epochs", "active"],
        );

        for (label, sql, parameters, continuation) in [
            (
                "initial mask page",
                SELECTED_MASK_PAGE_INITIAL_SQL,
                vec![Value::Text("java".into())],
                false,
            ),
            (
                "continuation mask page",
                SELECTED_MASK_PAGE_CONTINUATION_SQL,
                vec![Value::Text("java".into()), Value::Text(String::new())],
                true,
            ),
        ] {
            let plan = explain_plan(ready.connection(), sql, parameters);
            let position = required_plan_step(
                &plan,
                label,
                &["SEARCH masks", "PRIMARY KEY", "storage_language=?"],
            );
            assert_eq!(position, 0, "{label} must start at the bounded mask input");
            if continuation {
                assert!(
                    plan[position].contains("persisted_relative_path>?"),
                    "continuation mask page must seek after its path cursor: {plan:#?}"
                );
            }
            assert_plan_has_no_hazards(&plan, label, &["masks"]);
        }

        let mask_base = explain_plan(
            ready.connection(),
            SELECTED_MASK_BASE_SQL,
            vec![
                Value::Text("java".into()),
                Value::Text("src/0000.java".into()),
            ],
        );
        assert_plan_order(
            &mask_base,
            "masked base point lookup",
            &[
                (
                    "selected revision",
                    &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "selected version",
                    &[
                        "SEARCH versions",
                        "workspace_id=?",
                        "lang=?",
                        "generation=?",
                        "rel_path=?",
                        "valid_from<?",
                    ],
                ),
            ],
        );
        let mask_base_version = required_plan_step(
            &mask_base,
            "masked base point lookup",
            &[
                "SEARCH versions",
                "workspace_id=?",
                "lang=?",
                "generation=?",
            ],
        );
        assert_workspace_snapshot_path_seek(
            &mask_base,
            mask_base_version,
            "masked base point lookup",
        );
        assert_plan_has_no_hazards(
            &mask_base,
            "masked base point lookup",
            &["selected", "versions"],
        );

        for (label, sql, parameters, continuation) in [
            (
                "initial selected mount page",
                selected_mount_status_sql(false),
                vec![Value::Text("java".into())],
                false,
            ),
            (
                "continuation selected mount page",
                selected_mount_status_sql(true),
                vec![
                    Value::Text("java".into()),
                    Value::Text(String::new()),
                    Value::Integer(0),
                ],
                true,
            ),
        ] {
            let plan = explain_plan(ready.connection(), sql, parameters);
            assert_plan_order(
                &plan,
                label,
                &[
                    (
                        "language input",
                        &["SEARCH languages", "PRIMARY KEY", "storage_language=?"],
                    ),
                    (
                        "selected revision",
                        &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                    ),
                    (
                        "selected versions",
                        &[
                            "SEARCH versions",
                            "workspace_id=?",
                            "lang=?",
                            "generation=?",
                        ],
                    ),
                    (
                        "overlay mask",
                        &[
                            "SEARCH masks",
                            "PRIMARY KEY",
                            "storage_language=?",
                            "persisted_relative_path=?",
                        ],
                    ),
                    (
                        "blob identity",
                        &[
                            "SEARCH blobs",
                            "sqlite_autoindex_blobs_1",
                            "blob_oid=?",
                            "lang=?",
                        ],
                    ),
                    (
                        "blob completeness",
                        &["SEARCH meta", "PRIMARY KEY", "blob_id=?"],
                    ),
                    (
                        "resolution interior",
                        &["SEARCH interiors", "PRIMARY KEY", "blob_id=?"],
                    ),
                ],
            );
            let versions = required_plan_step(
                &plan,
                label,
                &[
                    "SEARCH versions",
                    "workspace_id=?",
                    "lang=?",
                    "generation=?",
                ],
            );
            assert_workspace_snapshot_path_seek(&plan, versions, label);
            if continuation {
                assert!(
                    plan[versions].contains("rel_path>?")
                        || plan[versions].contains("(rel_path,valid_from)>(?,?)"),
                    "continuation mount page must seek after its storage cursor: {plan:#?}"
                );
            }
            assert_plan_has_no_hazards(
                &plan,
                label,
                &[
                    "languages",
                    "selected",
                    "versions",
                    "masks",
                    "blobs",
                    "meta",
                    "interiors",
                ],
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("resolution_semantic_terms")),
                "mount inventory must not read fact-family payloads: {plan:#?}"
            );
        }

        let mount = &ready.mounts().unwrap()[0];
        let legacy = explain_plan(
            ready.connection(),
            "SELECT 1 FROM temp.workspace_files AS files
             WHERE files.lang = ?1 AND files.generation = ?2 AND files.blob_oid = ?3
             LIMIT 1",
            vec![
                Value::Text("java".into()),
                Value::Integer(mount.generation()),
                Value::Text(mount.blob_oid().to_string()),
            ],
        );
        assert_plan_order(
            &legacy,
            "legacy workspace blob membership",
            &[
                (
                    "selected revision",
                    &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "selected blob version",
                    &[
                        "SEARCH versions",
                        "COVERING INDEX",
                        "idx_workspace_file_versions_snapshot_blob",
                        "workspace_id=?",
                        "lang=?",
                        "generation=?",
                        "blob_oid=?",
                        "valid_from<?",
                    ],
                ),
            ],
        );
        assert_plan_has_no_hazards(
            &legacy,
            "legacy workspace blob membership",
            &["selected", "versions"],
        );
        assert!(
            legacy
                .iter()
                .all(|detail| !detail.contains("idx_workspace_file_versions_snapshot_path")),
            "legacy blob membership must retain its blob-oriented index: {legacy:#?}"
        );
    }
    #[test]
    fn named_manifest_counts_round_trip_in_family_order() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let mut ready = fixture.open_ready(&[]);
        let expected = std::array::from_fn(|index| u64::try_from(index + 1).unwrap());
        let mut mount = ready.mounts().unwrap()[0].clone();
        mount.manifest_counts = ResolutionManifestCounts::from_array(expected);
        let staged = StagedReadySelection {
            workspace_id: ready.workspace_id().to_owned(),
            languages: ready.languages().unwrap().to_vec(),
            overlay_masks: ready.overlay_masks().unwrap().to_vec(),
            mounts: vec![mount],
            fingerprint: ready.fingerprint(),
            expected_transient_replacement_count: ready.expected_transient_replacement_count(),
        };
        let tx = ready.conn.transaction().unwrap();
        // This test deliberately replaces the selected mount rows.
        brokk_bifrost_analysis::analyzer::store::resolution_selection::drop_selected_mount_guards_for_test(&tx).unwrap();
        tx.execute("DELETE FROM temp.selected_resolution_mounts", [])
            .unwrap();
        assert!(persist_selected_inventory(&tx, &staged, &CancellationToken::default()).unwrap());
        tx.commit().unwrap();

        let count_sql = format!(
            "SELECT {} FROM temp.selected_resolution_mounts WHERE mount_ordinal = 0",
            RESOLUTION_MANIFEST_COUNT_COLUMNS.join(", ")
        );
        let named_counts = ready
            .connection()
            .query_row(&count_sql, [], |row| {
                (0..RESOLUTION_MANIFEST_COUNT_COLUMNS.len())
                    .map(|index| row.get::<_, u64>(index))
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
            .unwrap();
        assert_eq!(named_counts, expected);
        assert!(
            (0..RESOLUTION_MANIFEST_COUNT_COLUMNS.len())
                .all(|index| staged.mounts[0].manifest_counts().get(index) == expected[index])
        );
    }
    #[test]
    fn empty_requested_language_set_retains_explicit_workspace_identity() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(0);
        let ready = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &WorkspaceSnapshots::default(),
                &[],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            _ => panic!("empty exact selection must be Ready"),
        };
        assert_eq!(ready.workspace_id(), WORKSPACE_ID);
        assert!(ready.languages().unwrap().is_empty());
        assert!(ready.mounts().unwrap().is_empty());
    }
    #[test]
    fn duplicate_or_cross_workspace_selection_input_fails_before_publication() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(0);
        let duplicate_languages = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &fixture.snapshots,
            &[fixture.language(), fixture.language()],
            &[],
            &CancellationToken::default(),
        );
        let duplicate_languages = match duplicate_languages {
            Err(error) => error,
            Ok(_) => panic!("duplicate languages must fail before publication"),
        };
        assert!(
            duplicate_languages
                .to_string()
                .contains("duplicate selected resolution language")
        );

        let duplicate_masks = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &fixture.snapshots,
            &[fixture.language()],
            &[
                SelectedResolutionOverlayMask::replacement("java", "src/New.java"),
                SelectedResolutionOverlayMask::removal("java", "src/New.java"),
            ],
            &CancellationToken::default(),
        );
        let duplicate_masks = match duplicate_masks {
            Err(error) => error,
            Ok(_) => panic!("duplicate masks must fail before publication"),
        };
        assert!(
            duplicate_masks
                .to_string()
                .contains("duplicate selected resolution mask")
        );

        let mut foreign_snapshots = fixture.snapshots.clone();
        foreign_snapshots.get_mut("java").unwrap().workspace_id =
            WorkspaceId("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        let foreign = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &foreign_snapshots,
            &[fixture.language()],
            &[],
            &CancellationToken::default(),
        );
        let foreign = match foreign {
            Err(error) => error,
            Ok(_) => panic!("cross-workspace snapshots must fail before publication"),
        };
        assert!(foreign.to_string().contains("different workspace"));
    }
    #[test]
    fn overlay_masks_keep_suppressed_base_and_replacement_obligations_separate() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(3);
        let masks = [
            SelectedResolutionOverlayMask::replacement("java", "src/0000.java"),
            SelectedResolutionOverlayMask::removal("java", "src/0001.java"),
            SelectedResolutionOverlayMask::replacement("java", "src/new.java"),
        ];
        let ready = fixture.open_ready(&masks);
        assert_eq!(ready.mounts().unwrap().len(), 1);
        assert_eq!(
            ready.mounts().unwrap()[0].persisted_relative_path(),
            "src/0002.java"
        );
        assert_eq!(ready.overlay_masks().unwrap().len(), 3);
        assert_eq!(
            ready
                .overlay_masks()
                .unwrap()
                .iter()
                .filter(|mask| mask.masked_base().is_some())
                .count(),
            2
        );
        assert_eq!(ready.expected_transient_replacement_count(), 2);
        assert_eq!(ready.languages().unwrap()[0].expected_base_mount_count(), 3);
        assert_eq!(ready.languages().unwrap()[0].masked_base_mount_count(), 2);
        assert_eq!(
            ready.languages().unwrap()[0].expected_unmasked_mount_count(),
            1
        );
    }
    #[test]
    fn cached_content_mounts_replace_masked_paths_without_transient_count() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let second_content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached-again.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let ready = fixture
            .store
            .open_selected_resolution_mount_inventory_with_content_mounts(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[
                    SelectedResolutionOverlayMask::replacement("java", "src/cached.java"),
                    SelectedResolutionOverlayMask::replacement("java", "src/cached-again.java"),
                ],
                &[content_mount, second_content_mount],
                &CancellationToken::default(),
            )
            .unwrap();
        let ready = match ready {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            _ => panic!("cached content mount should be ready"),
        };
        assert_eq!(ready.mounts().unwrap().len(), 3);
        assert_eq!(
            ready.mounts().unwrap()[0].persisted_relative_path(),
            "src/0000.java"
        );
        assert_eq!(
            ready.mounts().unwrap()[1].persisted_relative_path(),
            "src/cached-again.java"
        );
        assert_eq!(
            ready.mounts().unwrap()[2].persisted_relative_path(),
            "src/cached.java"
        );
        assert!(
            ready.mounts().unwrap()[1..]
                .iter()
                .all(|mount| mount.file_version_id().is_none())
        );
        assert_ne!(
            ready.mounts().unwrap()[1].fragment_id(),
            ready.mounts().unwrap()[2].fragment_id()
        );
        assert_eq!(ready.expected_transient_replacement_count(), 0);
        assert_eq!(ready.languages().unwrap()[0].expected_base_mount_count(), 1);
        assert_eq!(ready.languages().unwrap()[0].masked_base_mount_count(), 0);
    }
    #[test]
    fn cached_content_mount_requires_a_published_interior() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        let content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        fixture.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
        });
        let outcome = fixture
            .store
            .open_selected_resolution_mount_inventory_with_content_mounts(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[SelectedResolutionOverlayMask::replacement(
                    "java",
                    "src/cached.java",
                )],
                &[content_mount],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingInterior { .. }
            )
        ));
    }
    #[test]
    fn bootstrap_generation_without_analysis_epoch_is_current() {
        let bootstrap = crate::selection_fixture_support::JvmSelectionFixture::bootstrap(1);
        let epoch_rows = bootstrap.store.conn.execute(|conn| {
            conn.query_row("SELECT COUNT(*) FROM analysis_epochs", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap()
        });
        assert_eq!(epoch_rows, 0);
        let ready = bootstrap.open_ready(&[]);
        assert_eq!(ready.languages().unwrap()[0].generation(), 0);
        drop(ready);

        let non_bootstrap = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        non_bootstrap.store.conn.execute(|conn| {
            conn.execute("DELETE FROM analysis_epochs WHERE lang = 'java'", [])
                .unwrap();
        });
        let stale = non_bootstrap
            .store
            .open_selected_resolution_mount_inventory(
                &non_bootstrap.workspace_id,
                &non_bootstrap.snapshots,
                &[non_bootstrap.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            stale,
            SelectedResolutionMountInventoryOutcome::Stale(
                SelectedResolutionStale::AnalysisGeneration { .. }
            )
        ));
    }
    #[test]
    fn missing_interior_and_incomplete_parent_cannot_disappear_from_inventory() {
        let missing = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        missing.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
        });
        let outcome = missing
            .store
            .open_selected_resolution_mount_inventory(
                &missing.workspace_id,
                &missing.snapshots,
                &[missing.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingInterior { .. }
            )
        ));

        let incomplete = crate::selection_fixture_support::JvmSelectionFixture::new(1);
        incomplete.store.conn.execute(|conn| {
            conn.execute("UPDATE blob_meta SET is_complete = 0", [])
                .unwrap();
        });
        let outcome = incomplete
            .store
            .open_selected_resolution_mount_inventory(
                &incomplete.workspace_id,
                &incomplete.snapshots,
                &[incomplete.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::IncompleteParsedBlob { .. }
            )
        ));
    }

    use rusqlite::params;
}
