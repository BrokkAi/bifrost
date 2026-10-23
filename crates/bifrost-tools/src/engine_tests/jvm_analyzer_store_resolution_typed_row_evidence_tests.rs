#[cfg(test)]
mod jvm_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store::resolution_typed::TypedRowEvidence;

    use brokk_bifrost_analysis::native_resolution_test_support::SelectedTypedFactSource;
    use brokk_bifrost_analysis::native_resolution_test_support::SharedNameInterner;
    use std::collections::BTreeSet;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::resolution_typed::FRONTIER_SOURCE_READY_SQL;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredIntrinsicSeed;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFrontier;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PolledCompletionAccumulator;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::SelectedGapReasonProvenance;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

    use brokk_bifrost_analysis::analyzer::store::resolution_typed::SelectedResolutionTypedSource;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::store::StoreError;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactPageVisitor;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactReadOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution::TypedFactRelation;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactRequest;

    use rusqlite::types::Value;

    use brokk_bifrost_analysis::analyzer::store::resolution_typed::shared_request_probe;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFragment;

    use brokk_bifrost_analysis::analyzer::resolution::model::TypedFrontierState;

    #[test]
    fn selected_hierarchy_terminals_preserve_mounts_and_cancellation() {
        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

        use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionGapKind, ResolutionSiteId};
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
            2,
            "class Base {} class Box extends Base {}",
        );
        let selection = fixture.open_ready(&[]);
        let origin = LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal);
        let gaps = selection.connection().prepare(
            "SELECT mount.mount_ordinal, gap.reason, gap.site FROM temp.selected_resolution_mounts mount JOIN main.resolution_gap_reasons gap ON gap.blob_id=mount.blob_id WHERE gap.origin=?1 ORDER BY mount.mount_ordinal,gap.reason"
        ).unwrap().query_map([brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(origin)], |row| {
            let mount: u32 = row.get(0)?;
            Ok(SelectedGapReasonProvenance::new(
                BindingFragmentId::at_ordinal(mount), SemanticId::local(mount,row.get(1)?),
                ResolutionSiteId::new(row.get(2)?), origin,
            ))
        }).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            gaps.len(),
            4,
            "each mount has Base's implicit and Box's explicit superclass obligations: {gaps:?}"
        );
        let source = SelectedResolutionTypedSource::new_on_demand(&selection);
        let rows = source
            .hierarchy_terminal_nodes(&gaps, &CancellationToken::new())
            .unwrap()
            .unwrap();
        assert_eq!(rows.len(), gaps.len(), "{rows:?}");
        assert_eq!(
            rows.iter()
                .map(|(_, node)| *node)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        for ((reason, node), gap) in rows.iter().zip(&gaps) {
            assert_eq!(*reason, gap.reason());
            assert_eq!(node.ordinal(), Some(gap.fragment().ordinal()));
        }
        assert!(
            source
                .hierarchy_terminal_nodes(
                    &gaps,
                    &CancellationToken::cancel_after_checks_for_test(0)
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            source
                .hierarchy_terminal_nodes(&gaps, &CancellationToken::new())
                .unwrap()
                .unwrap(),
            rows
        );
    }
    #[test]
    fn frontier_completion_validates_requested_authority_without_unrelated_mounts() {
        for damage in ["unrelated", "missing", "stale", "withdrawn_blob"] {
            let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
                2,
                "package demo; class Model { int value = 1; }",
            );
            let selection = fixture.open_ready(&[]);
            let (blob, key): (i64, u32) = selection.connection().query_row(
                "SELECT m.blob_id,f.slot FROM temp.selected_resolution_mounts m JOIN main.resolution_type_frontiers f ON f.blob_id=m.blob_id WHERE m.mount_ordinal=0 LIMIT 1",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            let slot = SemanticId::local(0, key);
            let source = SelectedResolutionTypedSource::new_on_demand(&selection);
            let read = |token: &CancellationToken| {
                let mut rows = Vec::new();
                let outcome = source.visit_type_frontier_completion_pages(
                    TypedFactRequest::new(&[slot]),
                    token,
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        rows.extend_from_slice(page);
                        Ok(true)
                    }),
                )?;
                Ok::<_, StoreError>((outcome, rows))
            };
            let live = CancellationToken::new();
            let before = if damage == "unrelated" {
                let (_, before) = read(&live).unwrap();
                assert!(!before.is_empty());
                Some(before)
            } else {
                None
            };
            match damage {
                "withdrawn_blob" => {
                    // Sealed source requirements cannot be edited independently.
                    // Parsed-blob withdrawal lawfully cascades both publication
                    // authorities; this is not isolated readiness corruption.
                    assert_eq!(
                        fixture
                            .store
                            .conn
                            .lock()
                            .unwrap()
                            .execute("DELETE FROM blobs WHERE id=?1", [blob],)
                            .unwrap(),
                        1
                    );
                    assert!(
                        !selection
                            .connection()
                            .prepare(FRONTIER_SOURCE_READY_SQL)
                            .unwrap()
                            .exists([blob])
                            .unwrap()
                    );
                }
                _ => {
                    let damaged_blob = if damage == "unrelated" {
                        selection
                            .persisted_mount_record(SelectedResolutionMountOrdinal::new(1))
                            .unwrap()
                            .unwrap()
                            .blob_id()
                    } else {
                        blob
                    };
                    let writer = fixture.store.conn.lock().unwrap();
                    let sql = if damage == "missing" {
                        "DELETE FROM resolution_fragment_interiors WHERE blob_id=?1"
                    } else {
                        "UPDATE resolution_fragment_interiors SET interior_digest=zeroblob(32) WHERE blob_id=?1"
                    };
                    assert_eq!(writer.execute(sql, [damaged_blob]).unwrap(), 1);
                }
            }
            if damage == "unrelated" {
                let (outcome, after) = read(&live).unwrap();
                assert!(outcome.is_exhausted());
                assert_eq!(Some(after), before);
            } else {
                assert!(
                    read(&live).is_err(),
                    "requested {damage} must not become an empty answer"
                );
            }
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let (outcome, rows) = read(&cancelled).unwrap();
            assert!(outcome.is_cancelled());
            assert!(rows.is_empty());
        }
    }
    #[test]
    fn invocation_role_reader_is_keyed_under_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::plan_rows;

        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        for statistics in PlannerStatisticsState::BOTH {
            let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(32);
            let writer = fixture.store.conn.lock().unwrap();
            statistics.install(&writer);
            let query = pinned("invocation_roles_for_references");
            let plan = plan_rows(&writer, &query).unwrap();
            for alias in ["site", "role"] {
                assert!(
                    plan.iter()
                        .any(|row| row.contains(&format!("SEARCH {alias} "))),
                    "{statistics:?}: {plan:?}"
                );
                assert!(
                    !plan
                        .iter()
                        .any(|row| row.contains(&format!("SCAN {alias}"))),
                    "{statistics:?}: {plan:?}"
                );
            }
            assert!(
                !plan
                    .iter()
                    .any(|row| row.contains("AUTOMATIC") || row.contains("TEMP B-TREE")),
                "{statistics:?}: {plan:?}"
            );
        }
    }
    #[test]
    fn frontier_source_visibility_pin_is_keyed_under_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::plan_rows;

        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::StatementStatus;
        for statistics in PlannerStatisticsState::BOTH {
            let mut tiny = Vec::new();
            let mut keyed = Vec::new();
            for count in [2, 32, 64] {
                let fixture = crate::selection_fixture_support::JvmSelectionFixture::new(count);
                let writer = fixture.store.conn.lock().unwrap();
                statistics.install(&writer);
                let marker_count: usize = writer
                    .query_row(
                        "SELECT COUNT(*) FROM source_java_declaration_manifests",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(marker_count, count);
                let (first, last): (i64, i64) = writer
                    .query_row(
                        "SELECT MIN(blob_id),MAX(blob_id) FROM resolution_fragment_interiors",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let mut measured = Vec::new();
                for (blob, expected) in [(first, true), (last, true), (-1, false)] {
                    let mut query = pinned("frontier_source_ready");
                    query.params = vec![Value::Integer(blob)];
                    let plan = plan_rows(&writer, &query).unwrap();
                    for step in &plan {
                        if step.starts_with("SCAN ") {
                            assert!(
                                marker_count <= 2 && step == "SCAN java_marker LEFT-JOIN",
                                "{statistics:?}, markers={marker_count}: {plan:?}"
                            );
                        }
                    }
                    if marker_count > 2 {
                        assert!(
                            plan.iter().any(|step| step
                                .starts_with("SEARCH java_marker USING INTEGER PRIMARY KEY")),
                            "{statistics:?}, markers={marker_count}: {plan:?}"
                        );
                    }
                    let mut statement = writer.prepare(&query.sql).unwrap();
                    assert_eq!(statement.exists([blob]).unwrap(), expected);
                    measured.push(statement.get_status(StatementStatus::VmStep));
                }
                if count == 2 {
                    tiny = measured;
                } else {
                    assert!(
                        measured
                            .iter()
                            .zip(&tiny)
                            .all(|(large, small)| large <= small),
                        "{statistics:?}: tiny={tiny:?}, markers={marker_count}, work={measured:?}"
                    );
                    if count == 32 {
                        keyed = measured;
                    } else {
                        assert_eq!(measured, keyed, "{statistics:?}: keyed growth must be flat");
                    }
                }
            }
        }
    }
    #[test]
    fn actual_mixed_intrinsic_reader_retains_stage_evidence_on_stop_and_cancel() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;

        let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
            1,
            "package demo; class Model { int value = 1; }",
        );
        let selection = fixture.open_ready(&[]);
        let (host, key): (u32, u32) = selection.connection().query_row(
            "SELECT m.mount_ordinal,s.slot FROM temp.selected_resolution_mounts m JOIN main.resolution_intrinsic_seeds s ON s.blob_id=m.blob_id LIMIT 1",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        let slot = SemanticId::local(host, key);
        let source = SelectedResolutionTypedSource::new_on_demand(&selection);
        let mut ordinary = Vec::new();
        assert!(
            source
                .visit_intrinsic_seed_pages_for_slots(
                    TypedFactRequest::new(&[slot]),
                    &CancellationToken::new(),
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        ordinary.extend_from_slice(page);
                        Ok(true)
                    }),
                )
                .unwrap()
                .is_exhausted()
        );
        assert!(!ordinary.is_empty());
        let base = ordinary[0].row();
        let stage_completion =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::context_local(73),
            )]);
        let stage_slot = SemanticId::context_local(74);
        let seed = LoweredIntrinsicSeed::new(
            base.kind(),
            base.spelling(),
            TypedFrontierState::new(
                stage_slot,
                base.frontier().possible_values().to_vec(),
                stage_completion.clone(),
            ),
        );
        let mut frontiers = Vec::new();
        assert!(
            source
                .visit_typed_frontier_pages(
                    TypedFactRequest::new(&[slot]),
                    &CancellationToken::new(),
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        frontiers
                            .extend(page.iter().map(|row| {
                                LoweredTypedFrontier::new(stage_slot, row.row().role())
                            }));
                        Ok(true)
                    }),
                )
                .unwrap()
                .is_exhausted()
        );
        assert!(!frontiers.is_empty());
        let fragment = LoweredTypedFragment::new(
            BindingFragmentId::at_ordinal(host),
            Language::Java,
            frontiers,
            vec![],
            vec![seed],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        selection.with_owned_temp_transaction(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,?1,zeroblob(32),zeroblob(32))", [host])?;
            assert!(brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::insert_typed_fragment(
                connection, 1, SelectedResolutionMountOrdinal::new(host), &fragment, &CancellationToken::new(),
            )?);
            Ok(SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
        let shared_name = selection
            .shared_name_table()
            .interner(selection.connection())
            .intern([91; 32]);
        let shared = SemanticId::shared_name(shared_name);
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_type_frontiers(host_ordinal,producer_id,sequence,slot_shared,role) VALUES(?1,1,901,?2,0)", rusqlite::params![host,shared_name.get()])?;
            Ok(())
        }).unwrap();
        shared_request_probe::reset();
        let mut completions = Vec::new();
        assert!(
            source
                .visit_type_frontier_completion_pages(
                    TypedFactRequest::new(&[slot, stage_slot, shared]),
                    &CancellationToken::new(),
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        completions.extend_from_slice(page);
                        Ok(true)
                    }),
                )
                .unwrap()
                .is_exhausted()
        );
        for requested in [slot, stage_slot, shared] {
            assert!(
                completions.iter().any(|row| row.frontier() == requested),
                "{completions:?}"
            );
        }
        assert_eq!(
            shared_request_probe::observed(TypedFactRelation::TypeFrontierCompletionFrontier),
            (0, 0)
        );
        for cancel in [false, true] {
            let cancellation = CancellationToken::new();
            let mut emitted = Vec::new();
            let outcome = source
                .visit_intrinsic_seed_pages_for_slots(
                    TypedFactRequest::new(&[slot, stage_slot]),
                    &cancellation,
                    &mut TypedFactPageVisitor::with_maximum_rows(
                        &mut |page| {
                            emitted.extend_from_slice(page);
                            if cancel {
                                cancellation.cancel();
                            }
                            Ok(false)
                        },
                        1,
                    ),
                )
                .unwrap();
            assert_eq!(emitted, ordinary[..1]);
            let live = CancellationToken::new();
            let mut evidence = PolledCompletionAccumulator::new(&live);
            for row in &ordinary {
                row.include_evidence(&mut evidence);
            }
            evidence.include(&stage_completion);
            let expected = evidence.finish_semantic().0;
            assert_eq!(
                outcome,
                if cancel {
                    TypedFactReadOutcome::cancelled(expected)
                } else {
                    TypedFactReadOutcome::stopped(expected)
                }
            );
        }
    }
}
