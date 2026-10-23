#[cfg(test)]
mod jvm_extraction_tests {

    use rusqlite::params;

    use std::collections::HashMap;

    #[test]
    fn declaration_visibility_key_batches_seek_without_same_blob_fanout() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::StatementStatus;

        let mut baseline_work = HashMap::new();
        for declarations in [256, 2048, 4096] {
            // Bound physical lines so publication reaches the planner-work assertions.
            let methods = (0..declarations)
                .map(|index| format!("public void method{index}() {{}}\n"))
                .collect::<String>();
            let fixture = crate::selection_fixture_support::JvmSelectionFixture::custom_source(
                1,
                &format!("class Example {{ {methods} }}"),
            );
            let conn = fixture.store.conn.lock().unwrap();
            let blob: i64 = conn
                .query_row(
                    "SELECT blob_id FROM resolution_fragment_interiors LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let all = conn
            .prepare("SELECT definition_semantic_key, visibility FROM resolution_declaration_visibility_properties WHERE blob_id=?1 ORDER BY definition_semantic_key")
            .unwrap()
            .query_map([blob], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
            assert!(
                all.len() >= declarations,
                "real published declarations: {all:?}"
            );
            for statistics in PlannerStatisticsState::BOTH {
                statistics.install(&conn);
                let subject = pinned("resolution_declaration_visibilities_by_definition");
                for arity in [1, 16, 64, 256] {
                    for (case, keys) in [
                        all.iter()
                            .take(arity)
                            .map(|(key, _)| *key)
                            .collect::<Vec<_>>(),
                        vec![i64::from(u32::MAX); arity],
                        vec![all[0].0; arity],
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let expected = all
                            .iter()
                            .filter(|(key, _)| keys.contains(key))
                            .cloned()
                            .collect::<Vec<_>>();
                        let payload = serde_json::to_string(&keys).unwrap();
                        let mut statement = conn.prepare(&subject.sql).unwrap();
                        let mut actual = statement
                            .query_map(params![blob, payload], |row| {
                                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        actual.sort_unstable();
                        assert_eq!(
                            actual, expected,
                            "{statistics:?}, declarations={declarations}, keys={keys:?}"
                        );
                        let vm = statement.get_status(StatementStatus::VmStep);
                        let plan = conn
                            .prepare(&format!("EXPLAIN QUERY PLAN {}", subject.sql))
                            .unwrap()
                            .query_map(params![blob, payload], |row| row.get::<_, String>(3))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let work_key = (format!("{statistics:?}"), arity, case);
                        // SQLite's captured statistics move one constant-cost
                        // manifest lookup ahead of the boundary seek once the blob
                        // crosses 2048 declarations. That is a fixed planner cost:
                        // 2048 and 4096 report the same VmStep count. Keep the
                        // 256-vs-2048 comparison under the statistics-free planner,
                        // and compare 2048 with 4096 under both planners, so this
                        // pin still rejects work that grows with unrelated
                        // declarations without pinning the planner's constant join
                        // order.
                        if statistics == PlannerStatisticsState::Representative
                            && declarations == 2048
                        {
                            baseline_work.insert(work_key, vm);
                        } else if let Some(baseline) = baseline_work.get(&work_key) {
                            assert_eq!(
                                vm, *baseline,
                                "same requested batch must not grow with unrelated declarations: {statistics:?}, declarations={declarations}, keys={keys:?}: {plan:?}"
                            );
                        } else {
                            baseline_work.insert(work_key, vm);
                        }
                        for required in [
                            "SEARCH site USING INDEX sqlite_autoindex_resolution_semantic_sites_2 (blob_id=? AND semantic_role=? AND semantic_key=?)",
                            "SEARCH legacy USING PRIMARY KEY (blob_id=? AND definition_semantic_key=?)",
                            "SEARCH native USING PRIMARY KEY (blob_id=? AND source_site=?)",
                            "SEARCH visibility USING PRIMARY KEY (blob_id=? AND declaration_id=?)",
                        ] {
                            assert!(
                                plan.iter().any(|step| step.contains(required)),
                                "{statistics:?}, keys={keys:?}: {required}: {plan:?}"
                            );
                        }
                        // The materialized requested_boundaries CTE holds only the
                        // requested json_each keys. Each visibility compound arm may
                        // seek that bounded input through a transient covering index;
                        // this is the one automatic index shape the pin allows.
                        let boundary_seek = "SEARCH boundary USING AUTOMATIC COVERING INDEX (blob_id=? AND definition_semantic_key=?) LEFT-JOIN";
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("MATERIALIZE requested_boundaries")),
                            "{statistics:?}, keys={keys:?}: bounded boundary materialization: {plan:?}"
                        );
                        for automatic in plan.iter().filter(|step| step.contains("AUTOMATIC")) {
                            assert_eq!(
                                automatic.as_str(),
                                boundary_seek,
                                "{statistics:?}, keys={keys:?}: automatic index over unbounded input: {plan:?}"
                            );
                        }
                        for forbidden in [
                            "SCAN site",
                            "SCAN legacy",
                            "SCAN native",
                            "SCAN visibility",
                            "CO-ROUTINE",
                            "TEMP B-TREE",
                        ] {
                            assert!(
                                !plan.iter().any(|step| step.contains(forbidden)),
                                "{statistics:?}, keys={keys:?}: {forbidden}: {plan:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}
