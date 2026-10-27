#[cfg(test)]
mod rust_departing_row_evidence_tests_tests {
    use brokk_bifrost_analysis::native_resolution_test_support::SelectedTypedFactSource;

    use crate::engine_tests::rust_selection_fixture::RustSelectionFixtureExt;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

    use brokk_bifrost_analysis::analyzer::store::resolution_typed::SelectedResolutionTypedSource;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactPageVisitor;

    use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactRequest;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#5658: generic parameter classification scanned fragment interiors before its request table"
    )]
    fn typed_request_plans_drive_from_requested_keys() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::plan_rows;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::SelectionFixture;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

        for state in PlannerStatisticsState::BOTH {
            let fixture = SelectionFixture::custom_rust_source(
                32,
                "pub struct Model<T> { value: T } pub fn identity<U>(value: U) -> U { value }",
            );
            {
                let writer = fixture.store.conn.lock().unwrap();
                state.install(&writer);
                if state == PlannerStatisticsState::Representative {
                    // The shared 2026-09-04 capture predates these native
                    // tables. Use tract's 2026-10-19 cardinalities for this
                    // regression, without changing unrelated plan fixtures.
                    writer.execute_batch("DELETE FROM sqlite_stat1 WHERE tbl IN (
                        'resolution_fragment_interiors', 'resolution_semantic_sites',
                        'resolution_typed_fact_lookups', 'source_declarations',
                        'source_native_declaration_bridges');
                        DELETE FROM sqlite_stat4 WHERE tbl IN (
                        'resolution_fragment_interiors', 'resolution_semantic_sites',
                        'resolution_typed_fact_lookups', 'source_declarations',
                        'source_native_declaration_bridges');
                        INSERT INTO sqlite_stat1(tbl,idx,stat) VALUES
                        ('resolution_fragment_interiors','resolution_fragment_interiors','1229 1'),
                        ('resolution_semantic_sites','resolution_semantic_sites','439997 251 1'),
                        ('resolution_semantic_sites','sqlite_autoindex_resolution_semantic_sites_2','439997 251 126 1'),
                        ('resolution_typed_fact_lookups','resolution_typed_fact_lookups','55376 84 39 1'),
                        ('resolution_typed_fact_lookups','resolution_typed_fact_lookups_identity','55376 1001 251 1'),
                        ('source_declarations','source_declarations','77390 15 1'),
                        ('source_declarations','source_declarations_name_range','77390 15 1 1 1'),
                        ('source_declarations','source_declarations_occurrence','77390 15 1 1'),
                        ('source_native_declaration_bridges','source_native_declaration_bridges','73030 101 1'),
                        ('source_native_declaration_bridges','source_native_declaration_bridges_declaration','73030 101 1 1');
                        ANALYZE sqlite_schema;").unwrap();
                    writer.flush_prepared_statement_cache();
                }
            }
            fixture.store.recycle_readers_for_new_statistics();
            let selection = fixture.open_ready(&[]);
            let conn = selection.connection();
            let keys: Vec<(SelectedResolutionMountOrdinal, i64)> = conn
                .prepare(
                    "SELECT mount.mount_ordinal, semantic.semantic_key
                    FROM temp.selected_resolution_mounts mount
                    JOIN main.resolution_semantic_sites semantic ON semantic.blob_id=mount.blob_id
                    WHERE semantic.semantic_role='definition' AND semantic.namespace='type'
                    ORDER BY mount.mount_ordinal, semantic.semantic_key LIMIT 64",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        SelectedResolutionMountOrdinal::new(row.get(0)?),
                        row.get(1)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(keys.len(), 64);
            for arity in [1, 64] {
                let requests = serde_json::to_string(
                    &keys[..arity]
                        .iter()
                        .map(|(mount, key)| (mount.get(), *key))
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                for (name, outer, corpus) in [
                    (
                        "generic_parameter_declarations",
                        "request",
                        &["mount", "interior", "semantic", "bridge", "declaration"][..],
                    ),
                    ("qualified_route_mounts", "scope", &["m", "interior"][..]),
                    (
                        "selected_typed_shared_membership",
                        "r",
                        &["membership", "m", "scope", "interior"][..],
                    ),
                    (
                        "selected_typed_shared_membership_64",
                        "r",
                        &["membership", "m", "scope", "interior"][..],
                    ),
                ] {
                    let plan = plan_rows(conn, &pinned(name)).unwrap();
                    eprintln!("{state:?} arity={arity} {name}: {plan:?}");
                    let outer_position = plan
                        .iter()
                        .position(|row| row.starts_with(&format!("SCAN {outer}")))
                        .unwrap_or_else(|| panic!("{state:?} {name}: {plan:?}"));
                    for alias in corpus {
                        let position = plan
                            .iter()
                            .position(|row| row.starts_with(&format!("SEARCH {alias} ")))
                            .unwrap_or_else(|| panic!("{state:?} {name}: {plan:?}"));
                        assert!(outer_position < position, "{state:?} {name}: {plan:?}");
                        assert!(
                            !plan
                                .iter()
                                .any(|row| row.starts_with(&format!("SCAN {alias} "))
                                    || row == &format!("SCAN {alias}")),
                            "{state:?} {name}: {plan:?}"
                        );
                    }
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {name}: {plan:?}"
                    );
                }
                let mut query = pinned("generic_parameter_declarations");
                query.params = vec![rusqlite::types::Value::Text(requests.clone())];
                let read = |sql: &str| {
                    let mut rows: Vec<(i64, i64)> = conn
                        .prepare(sql)
                        .unwrap()
                        .query_map([&requests], |row| Ok((row.get(0)?, row.get(1)?)))
                        .unwrap()
                        .collect::<rusqlite::Result<_>>()
                        .unwrap();
                    rows.sort_unstable();
                    rows
                };
                let found = read(&query.sql);
                assert_eq!(
                    found,
                    read(&query.sql.replace("CROSS JOIN", "JOIN")),
                    "{state:?} arity={arity}"
                );
                if arity == 64 {
                    assert!(
                        !found.is_empty(),
                        "{state:?}: generic parameters must be present"
                    );
                }
            }
        }
    }

    #[test]
    fn rust_reason_owner_memo_rebases_shared_blob_and_preserves_terminals() {
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::SelectionFixture;
        let fixture = SelectionFixture::shared_rust_source(
            2,
            "pub trait Service { fn run<T>(&self, value: T); } fn main() { missing(); }",
        );
        let selection = fixture.open_ready(&[]);
        let (blob, reasons, expected) = {
            let connection = selection.connection();
            let blob: i64 = connection
                .query_row(
                    "SELECT blob_id FROM temp.selected_resolution_mounts WHERE mount_ordinal=0",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let reasons = connection
                .prepare(
                    "SELECT gap.reason, authority.semantic_key FROM resolution_gap_reasons gap
                 LEFT JOIN resolution_sites site ON site.blob_id=gap.blob_id
                   AND site.site=gap.site AND site.role=1
                 LEFT JOIN resolution_rust_declaration_authorities authority
                   ON authority.blob_id=site.blob_id AND authority.source_site=site.site
                 WHERE gap.blob_id=?1 ORDER BY gap.reason",
                )
                .unwrap()
                .query_map([blob], |row| {
                    Ok((row.get::<_, u32>(0)?, row.get::<_, Option<u32>>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                reasons.iter().any(|(_, owner)| owner.is_some()),
                "{reasons:?}"
            );
            assert!(
                reasons.iter().any(|(_, owner)| owner.is_none()),
                "{reasons:?}"
            );
            let expected = reasons
                .iter()
                .filter_map(|(reason, owner)| owner.map(|owner| (*reason, owner)))
                .collect::<Vec<_>>();
            (blob, reasons, expected)
        };
        let source = SelectedResolutionTypedSource::new_on_demand(&selection);
        let read = |ordinal, cancellation: &CancellationToken, keep_going| {
            let requested = reasons
                .iter()
                .map(|(reason, _)| SemanticId::local(ordinal, *reason))
                .collect::<Vec<_>>();
            let mut pages = Vec::new();
            let outcome = source
                .visit_rust_reason_owners(
                    TypedFactRequest::new(&requested),
                    cancellation,
                    &mut TypedFactPageVisitor::with_maximum_rows(
                        &mut |page| {
                            pages.push(page.to_vec());
                            Ok(keep_going)
                        },
                        1,
                    ),
                )
                .unwrap();
            (outcome, pages)
        };
        let live = CancellationToken::new();
        for ordinal in [0, 1, 0] {
            let (outcome, pages) = read(ordinal, &live, true);
            assert!(outcome.is_exhausted());
            assert_eq!(
                pages.into_iter().flatten().collect::<Vec<_>>(),
                expected
                    .iter()
                    .map(|(reason, owner)| {
                        (
                            SemanticId::local(ordinal, *reason),
                            SemanticId::local(ordinal, *owner),
                        )
                    })
                    .collect::<Vec<_>>()
            );
            let memo = selection.authority_request_memo().borrow();
            assert_eq!(memo.rust_reason_owners.len(), reasons.len());
            for (reason, owner) in &reasons {
                assert_eq!(
                    memo.rust_reason_owners[&(blob, i64::from(*reason))],
                    owner.map(i64::from)
                );
            }
        }
        let (outcome, pages) = read(1, &live, false);
        assert_eq!(
            outcome.terminal(),
            brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactReadTerminal::Stopped
        );
        assert_eq!(pages.len(), 1);
        let (outcome, pages) = read(0, &CancellationToken::cancel_after_checks_for_test(0), true);
        assert!(outcome.is_cancelled());
        assert!(pages.is_empty());
        drop(source);
        drop(selection);
        let fresh_selection = fixture.open_ready(&[]);
        assert!(
            fresh_selection
                .authority_request_memo()
                .borrow()
                .rust_reason_owners
                .is_empty()
        );
    }
}
