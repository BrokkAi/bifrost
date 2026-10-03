use super::*;
use crate::analyzer::Language;
use crate::analyzer::store::planner_statistics::pinned_plans::pinned;
use crate::analyzer::store::resolution_selection::tests::SelectionFixture;
use crate::analyzer::store::resolution_stage::{
    SelectedResolutionStage, SelectedResolutionStageOutcome, codec,
};
use crate::analyzer::store::resolution_typed::SelectedResolutionTypedSource;
use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
use rusqlite::{Connection, StatementStatus, params};

type Context = SelectedTypedRow<LoweredRustReferenceContext>;

fn collect(selection: &SelectedResolutionMountInventory<'_>, keys: &[SemanticId]) -> Vec<Context> {
    let mut answer = Vec::new();
    let mut receive = |page: &[Context]| {
        answer.extend_from_slice(page);
        Ok(true)
    };
    let outcome = SelectedResolutionTypedSource::new_on_demand(selection)
        .visit_rust_reference_context_pages(
            TypedFactRequest::new(keys),
            &CancellationToken::new(),
            &mut TypedFactPageVisitor::new(&mut receive),
        )
        .unwrap();
    assert!(outcome.is_exhausted());
    answer
}

#[test]
fn authenticated_capsule_contexts_join_ordinary_rows_and_preserve_stop_and_cancel() {
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
        for fixture in fixtures.into_iter().take(2) {
            assert!(!fixture.references.is_empty());
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
            let ResolutionContentPublicationOutcome::Ready(receipt) = store
                .publish_selected_resolution_capsule(owner, &fixture.host_path, prepared, &live)
                .unwrap()
            else {
                panic!("actual capsule publication");
            };
            cases.push((fixture, receipt));
        }
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
            panic!("actual selected macro hosts");
        };
        let stage = SelectedResolutionStage::new(&selection);
        let mut expected = Vec::new();
        for (fixture, receipt) in cases {
            let host = selection
                .mount_record_for_path(&owner.lang, &fixture.host_path)
                .unwrap()
                .unwrap();
            assert!(matches!(
                stage
                    .admit_capsule(*receipt, &host, fixture.dense, &[], &live)
                    .unwrap(),
                SelectedResolutionStageOutcome::Ready
            ));
            for source in fixture.references {
                let semantic = selection.connection().query_row(
                    "SELECT coordinate.runtime_key FROM temp.selected_resolution_stage_semantic_coordinates coordinate JOIN temp.selected_resolution_stage_producers producer USING(producer_id) WHERE coordinate.host_ordinal=?1 AND coordinate.dense_key=?2 AND producer.admission_id IS NOT NULL",
                    params![host.ordinal().get(),source.semantic_key.get()], |row| row.get::<_,i64>(0)).unwrap();
                expected.push(SelectedTypedRow::new(
                    BindingFragmentId::at_ordinal(host.ordinal().get()),
                    LoweredRustReferenceContext::new(
                        codec::decode_semantic(semantic),
                        source.source_site,
                        source.host_occurrence,
                        source.module_context,
                        source.module_declaration,
                    ),
                ));
            }
        }
        assert!(
            expected
                .iter()
                .all(|r| r.row().cfg_condition() == &RustCfgCondition::Always)
        );
        // Ordinary source authority is independently read from the persisted blob.
        let ordinary = selection.connection().query_row(
            "SELECT mount.mount_ordinal,source.semantic_key,source.source_site,source.source_occurrence,source.module_context,source.module_declaration,json(source.cfg_condition) FROM temp.selected_resolution_mounts mount JOIN main.resolution_rust_reference_contexts source USING(blob_id) LIMIT 1", [], |row| {
                let host = row.get::<_,u32>(0)?;
                Ok(SelectedTypedRow::new(BindingFragmentId::at_ordinal(host),LoweredRustReferenceContext::new(
                    SemanticId::local(host,row.get(1)?),ResolutionSiteId::new(row.get(2)?),SourceOccurrenceId::new(row.get(3)?),
                    SourceOccurrenceId::new(row.get(4)?),row.get::<_,Option<u32>>(5)?.map(SourceDeclarationId::new))
                    .with_cfg_condition(rust_authority::decode_cfg(&row.get::<_,String>(6)?))))
            }).unwrap();
        expected.push(ordinary);
        let keys = expected
            .iter()
            .map(|r| r.row().reference())
            .collect::<Vec<_>>();
        let actual = collect(&selection, &keys);
        assert_eq!(actual.len(), expected.len());
        for row in &expected {
            assert!(actual.contains(row), "missing {row:?}; actual={actual:?}");
        }
        let source = SelectedResolutionTypedSource::new_on_demand(&selection);
        let mut seen = Vec::new();
        let mut stop = |page: &[Context]| {
            seen.extend_from_slice(page);
            Ok(false)
        };
        let stopped = source
            .visit_rust_reference_context_pages(
                TypedFactRequest::new(&keys),
                &live,
                &mut TypedFactPageVisitor::with_maximum_rows(&mut stop, 1),
            )
            .unwrap();
        assert!(!stopped.is_exhausted());
        assert!(!stopped.is_cancelled());
        assert_eq!(seen.len(), 1);
        let during = CancellationToken::new();
        let callback_token = during.clone();
        let mut visited = 0;
        let mut cancel_after_page = |page: &[Context]| {
            visited += page.len();
            callback_token.cancel();
            Ok(true)
        };
        assert!(
            source
                .visit_rust_reference_context_pages(
                    TypedFactRequest::new(&keys),
                    &during,
                    &mut TypedFactPageVisitor::with_maximum_rows(&mut cancel_after_page, 1)
                )
                .unwrap()
                .is_cancelled()
        );
        assert_eq!(visited, 1);
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut reject = |_: &[Context]| -> Result<bool> {
            panic!("cancelled reader cannot visit");
        };
        assert!(
            source
                .visit_rust_reference_context_pages(
                    TypedFactRequest::new(&keys),
                    &cancelled,
                    &mut TypedFactPageVisitor::new(&mut reject)
                )
                .unwrap()
                .is_cancelled()
        );
    });
}

// These synthetic rows exercise storage decoding and planner growth only. The
// authenticated producer contract is exercised separately above.
fn insert_context(
    connection: &Connection,
    producer: i64,
    host: u32,
    semantic: SemanticId,
    n: u32,
) -> Context {
    let cell = codec::encode_semantic(semantic);
    let (key, shared) = if cell < 0 {
        (None, Some(-cell))
    } else {
        (Some(cell), None)
    };
    let cfg = match n % 4 {
        0 => RustCfgCondition::Always,
        1 => RustCfgCondition::Atom("feature=enabled".into()),
        2 => RustCfgCondition::NotAtom("test".into()),
        _ => RustCfgCondition::Unknown,
    };
    let declaration = n
        .is_multiple_of(2)
        .then(|| SourceDeclarationId::new(4000 + n));
    connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3,zeroblob(32))",params![producer,host,{let mut digest=[0u8;32];digest[..8].copy_from_slice(&producer.to_le_bytes());digest}]).unwrap();
    connection.execute("INSERT INTO temp.selected_resolution_stage_semantic_coordinates(host_ordinal,producer_id,dense_key,runtime_key,shared_id,identity_digest) VALUES(?1,?2,0,?3,?4,zeroblob(32))",params![host,producer,key,shared]).unwrap();
    connection.execute("INSERT INTO temp.selected_resolution_stage_reference_contexts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,jsonb(?9),0,NULL,NULL)",
        params![host,producer,key,shared,1000+n,2000+n,3000+n,declaration.map(|d|d.get()),rust_authority::encode_cfg(&cfg)]).unwrap();
    SelectedTypedRow::new(
        BindingFragmentId::at_ordinal(host),
        LoweredRustReferenceContext::new(
            semantic,
            ResolutionSiteId::new(1000 + n),
            SourceOccurrenceId::new(2000 + n),
            SourceOccurrenceId::new(3000 + n),
            declaration,
        )
        .with_cfg_condition(cfg),
    )
}

#[test]
fn capsule_context_keys_preserve_actual_scope_pairs_multiplicity_and_missing_rows() {
    let fixture = SelectionFixture::shared_blob(20);
    let selection = fixture.open_ready(&[]);
    let foreign = SemanticId::local(3, 23);
    let shared = SemanticId::shared_name(SharedNameId::interned(31));
    let high = SemanticId::context_local((1 << 53) + 101);
    let mut expected = Vec::new();
    selection.with_owned_temp_write(|connection| {
        for (p,h,k) in [(1,7,high),(2,13,high),(3,7,shared),(4,19,foreign),
            (5,7,SemanticId::context_local(501)),(6,7,SemanticId::context_local(601))] {
            let row = insert_context(connection,p,h,k,p as u32);
            if p<5 {expected.push(row);}
        }
        connection.execute("DELETE FROM temp.selected_resolution_stage_semantic_coordinates WHERE producer_id=5",[])?;
        connection.execute("DELETE FROM temp.selected_resolution_stage_reference_contexts WHERE producer_id=6",[])?;
        Ok(())
    }).unwrap();
    let keys = [
        high,
        shared,
        foreign,
        SemanticId::local(0, 31),
        SemanticId::shared_name(SharedNameId::interned(101)),
        SemanticId::context_local(501),
        SemanticId::context_local(601),
    ];
    // Direct stage read intentionally exercises false and foreign coordinates;
    // ordinary authority has its own coordinate validation in the combined seam.
    for scope in [vec![7, 13, 19], vec![3], vec![19], vec![]] {
        selection
            .with_owned_temp_write(|c| {
                c.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
                for h in &scope {
                    c.execute(
                        "INSERT INTO temp.selected_resolution_scope_mounts VALUES(?1)",
                        [h],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let mut actual = Vec::new();
        let mut receive = |page: &[Context]| {
            actual.extend_from_slice(page);
            Ok(true)
        };
        assert!(
            visit_rust_reference_context_pages(
                &selection,
                TypedFactRequest::new(&keys),
                &CancellationToken::new(),
                &mut TypedFactPageVisitor::new(&mut receive)
            )
            .unwrap()
            .is_exhausted()
        );
        let wanted = expected
            .iter()
            .filter(|r| scope.contains(&r.fragment().ordinal()))
            .collect::<Vec<_>>();
        assert_eq!(actual.len(), wanted.len());
        for row in wanted {
            assert!(actual.contains(row), "missing {row:?}; actual={actual:?}");
        }
    }
}

#[test]
fn bundled_capsule_context_plans_scale_with_dense_and_mixed_answers_under_both_statistics_states() {
    for statistics in PlannerStatisticsState::BOTH {
        for unrelated_host in [7, 19] {
            // Synthetic planner rows do not enter the production stage
            // lifecycle. Give each matrix case its own store and TEMP reader.
            let fixture = SelectionFixture::shared_blob(20);
            fixture.store.conn.execute(move |connection| {
                statistics.install(connection);
                connection.flush_prepared_statement_cache();
            });
            fixture.store.recycle_readers_for_new_statistics();
            let selection = fixture.open_ready(&[]);
            let expected = selection
                .with_owned_temp_write(|c| {
                    Ok((0..256)
                        .map(|n| {
                            insert_context(
                                c,
                                i64::from(n) + 1,
                                [7, 13, 19][n as usize % 3],
                                SemanticId::context_local((1 << 53) + u64::from(n)),
                                n,
                            )
                        })
                        .collect::<Vec<_>>())
                })
                .unwrap();
            let subject = pinned("stage_rust_reference_contexts");
            let mut baseline = Vec::new();
            for (start, growth) in [(0, 0), (0, 1), (1, 2048), (2048, 4096)] {
                if growth > 0 {
                    selection
                        .with_owned_temp_write(|c| {
                            for n in start..growth {
                                insert_context(
                                    c,
                                    i64::from(n) + 1000,
                                    unrelated_host,
                                    SemanticId::context_local(100000 + u64::from(n)),
                                    n,
                                );
                            }
                            Ok(())
                        })
                        .unwrap();
                }
                let mut measured = Vec::new();
                for arity in [1, 64, 256] {
                    for mixed in [false, true] {
                        let keys = (0..arity)
                            .map(|n| {
                                if mixed && n % 2 == 1 {
                                    SemanticId::context_local(200000 + n as u64)
                                } else {
                                    expected[n].row().reference()
                                }
                            })
                            .collect::<Vec<_>>();
                        let payload = super::super::typed::semantic_request_json(
                            TypedFactRequest::new(&keys),
                        );
                        let plan = selection
                            .connection()
                            .prepare(&format!("EXPLAIN QUERY PLAN {}", subject.sql))
                            .unwrap()
                            .query_map([&payload], |r| r.get::<_, String>(3))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        for index in [
                            "selected_resolution_stage_semantic_runtime",
                            "selected_resolution_stage_reference_context_identity",
                        ] {
                            assert!(
                                plan.iter().any(|s| s.contains(index)),
                                "{statistics:?}: {plan:?}"
                            );
                        }
                        assert!(
                            !plan.iter().any(|s| s.contains("SCAN coordinate")
                                || s.contains("SCAN context")
                                || s.contains("AUTOMATIC")
                                || s.contains("TEMP B-TREE")
                                || s.contains("CO-ROUTINE")),
                            "{statistics:?}: {plan:?}"
                        );
                        let mut statement = selection.connection().prepare(&subject.sql).unwrap();
                        let count = statement
                            .query_map([&payload], |r| r.get::<_, u32>("source_site"))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap()
                            .len();
                        assert_eq!(count, if mixed { arity.div_ceil(2) } else { arity });
                        let vm = statement.get_status(StatementStatus::VmStep);
                        assert!(
                            vm < (arity * 50 + 100) as i32,
                            "{statistics:?}, growth={growth}, arity={arity}, mixed={mixed}: {vm}; {plan:?}"
                        );
                        measured.push((arity, mixed, vm));
                        let mut actual = Vec::new();
                        let mut receive = |page: &[Context]| {
                            actual.extend_from_slice(page);
                            Ok(true)
                        };
                        assert!(
                            visit_rust_reference_context_pages(
                                &selection,
                                TypedFactRequest::new(&keys),
                                &CancellationToken::new(),
                                &mut TypedFactPageVisitor::new(&mut receive)
                            )
                            .unwrap()
                            .is_exhausted()
                        );
                        let wanted = expected[..arity]
                            .iter()
                            .enumerate()
                            .filter(|(n, _)| !mixed || n % 2 == 0)
                            .map(|(_, r)| r)
                            .collect::<Vec<_>>();
                        assert_eq!(actual.len(), wanted.len());
                        for row in wanted {
                            assert!(
                                actual.contains(row),
                                "{statistics:?}: missing {row:?}; actual={actual:?}"
                            );
                        }
                    }
                }
                if growth == 0 {
                    baseline = measured;
                } else if growth == 1 {
                    // Dense 256 visits the last context producer in the empty
                    // growth fixture. One later producer changes Next from EOF
                    // to one final IdxGT check. This terminal instruction is
                    // independent of how many unrelated producers follow it.
                    for ((arity, mixed, vm), (_, _, initial)) in measured.iter().zip(&baseline) {
                        let delta = *vm - *initial;
                        if *arity == 256 && !*mixed {
                            assert!(
                                (0..=1).contains(&delta),
                                "{statistics:?}, host={unrelated_host}: terminal delta {delta}; before={baseline:?}, after={measured:?}"
                            );
                        } else {
                            assert_eq!(
                                delta, 0,
                                "{statistics:?}, host={unrelated_host}: nonterminal shape changed; before={baseline:?}, after={measured:?}"
                            );
                        }
                    }
                    baseline = measured;
                } else {
                    assert_eq!(
                        measured, baseline,
                        "{statistics:?}, host={unrelated_host}, growth={growth}"
                    );
                }
            }
        }
    }
}
