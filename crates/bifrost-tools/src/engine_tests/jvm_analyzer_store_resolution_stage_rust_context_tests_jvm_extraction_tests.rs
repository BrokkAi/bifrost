#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::rust_context::tests::rust_wave2_root_test_support::Context as Context;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::model::SharedNameId;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactPageVisitor;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactRequest;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::rust_context::tests::insert_context;

    use brokk_bifrost_analysis::analyzer::store::resolution_stage::rust_context::visit_rust_reference_context_pages;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

    #[cfg(test)]
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    #[cfg(test)]
    use rusqlite::StatementStatus;

    #[test]
    fn capsule_context_keys_preserve_actual_scope_pairs_multiplicity_and_missing_rows() {
        let fixture = crate::selection_fixture_support::JvmSelectionFixture::shared_blob(20);
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
    fn bundled_capsule_context_plans_scale_with_dense_and_mixed_answers_under_both_statistics_states()
     {
        for statistics in PlannerStatisticsState::BOTH {
            for unrelated_host in [7, 19] {
                // Synthetic planner rows do not enter the production stage
                // lifecycle. Give each matrix case its own store and TEMP reader.
                let fixture =
                    crate::selection_fixture_support::JvmSelectionFixture::shared_blob(20);
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
                            let payload = brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::semantic_request_json(
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
                            let mut statement =
                                selection.connection().prepare(&subject.sql).unwrap();
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
                        for ((arity, mixed, vm), (_, _, initial)) in measured.iter().zip(&baseline)
                        {
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
}
