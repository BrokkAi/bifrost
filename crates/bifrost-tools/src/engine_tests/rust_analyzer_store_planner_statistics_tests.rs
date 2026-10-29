#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::Connection;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_core::cache_gc::STORE_STATISTICS_ENV;
    use brokk_bifrost_core::cache_gc::planner_statistics_repairs;
    use brokk_bifrost_core::cache_gc::planner_statistics_row_count;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::gitblob::test_repo::commit_all;

    use brokk_bifrost_core::gitblob::test_repo::init_repo;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::rust_tests_test_support::statistics_env_lock;
    #[test]
    #[hardwon(
        "#4990+#4995: Rust point readers repeated live alignment and dependency closure per lookup"
    )]
    fn rust_module_placement_readers_seek_materialized_selection_rows() {
        use brokk_bifrost_analysis::CancellationToken;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
            SelectedResolutionOverlayMask,
        };
        use brokk_bifrost_analysis::inline_project::InlineTestProject;
        use rusqlite::types::Value;

        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='placements'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={path='provider'}\n",
            )
            .file(
                "src/lib.rs",
                "pub mod child; pub mod inline { pub fn target() {} }",
            )
            .file(
                "src/child.rs",
                "pub fn caller() { crate::inline::target(); }",
            )
            .file("provider/Cargo.toml", "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n")
            .file("provider/src/lib.rs", "pub struct Item; #[macro_export] macro_rules! chosen { () => {} }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let workspace = {
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::WorkspaceId(
                conn.query_row(
                    "SELECT workspace_id FROM workspace_heads WHERE lang='rust'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            )
        };
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace, &["rust".into()])
            .unwrap();
        // Publication can replace summary rows without moving the workspace
        // revision. Both reader pools must invalidate that identical selection.
        store
            .execute_selection_publication(|conn| -> brokk_bifrost_analysis::analyzer::store::Result<()> {
                let tx = conn.transaction()?;
                tx.execute(
                    brokk_bifrost_analysis::analyzer::store::unit_summaries::DELETE_LANGUAGE_VERSIONS_SQL,
                    ["rust"],
                )?;
                tx.execute(
                    brokk_bifrost_core::cache_gc::DELETE_UNBOUND_SUMMARIES_SQL,
                    [],
                )?;
                tx.commit()?;
                Ok(())
            })
            .unwrap();
        let mut ordinary = store.read_conn_for_workspace(&snapshots).unwrap();
        assert_eq!(
            ordinary
                .query_row(
                    "SELECT count(*) FROM selected_rust_unit_summaries",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        {
            let conn = store.conn.lock().unwrap();
            store
                .select_writer_workspace_snapshots(&conn, &snapshots)
                .unwrap();
            assert_eq!(
                conn.query_row(
                    "SELECT count(*) FROM selected_rust_unit_summaries",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
        }
        store.reconcile_rust_crates(&snapshots["rust"]).unwrap();
        assert_eq!(
            store
                .workspace_snapshots_for_current_languages(&workspace, &["rust".into()])
                .unwrap(),
            snapshots
        );
        assert!(
            store.writer_selection.lock().unwrap().is_none(),
            "same-connection publication invalidates the writer fallback"
        );
        store
            .select_workspace_snapshots(&mut ordinary, &snapshots)
            .unwrap();
        let published: i64 = ordinary
            .query_row(
                "SELECT count(*) FROM selected_rust_unit_summaries",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            published > 0,
            "unchanged revision sees newly published units"
        );
        let counts = store.workspace_selection_counts_for_test();
        store
            .select_workspace_snapshots(&mut ordinary, &snapshots)
            .unwrap();
        assert_eq!(
            store.workspace_selection_counts_for_test(),
            counts,
            "unchanged publication reuses materialized units"
        );
        drop(ordinary);
        {
            let conn = store.conn.lock().unwrap();
            store
                .select_writer_workspace_snapshots(&conn, &snapshots)
                .unwrap();
            assert_eq!(
                conn.query_row(
                    "SELECT count(*) FROM selected_rust_unit_summaries",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                published
            );
        }
        // Reuse, then acquire a different masked selection, then restore it.
        // The fill runs only after the final input write in each acquisition.
        for masks in [
            vec![],
            vec![],
            vec![SelectedResolutionOverlayMask::removal(
                "rust",
                "src/child.rs",
            )],
            vec![],
        ] {
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &[SelectedResolutionLanguage::new("rust", Language::Rust)],
                    &masks,
                    &CancellationToken::default(),
                )
                .unwrap()
            else {
                panic!("complete selection");
            };
            let conn = selection.connection();
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM selected_rust_container_placements",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(count > 0, "selection must publish module placements");
            // Compare the completed table to the original live SELECT, including
            // aligned inline scopes. SQL text is a value, not source syntax.
            let select = SELECTED_MODULE_PLACEMENTS_FILL_SQL
                .split_once("INSERT INTO temp.selected_resolution_transient_placements\n")
                .unwrap()
                .1
                .split_once(';')
                .unwrap()
                .0;
            let equal: bool = conn.query_row(&format!(
                "WITH expected AS ({select}) SELECT NOT EXISTS(SELECT * FROM expected EXCEPT SELECT * FROM selected_resolution_transient_placements) AND NOT EXISTS(SELECT * FROM selected_resolution_transient_placements EXCEPT SELECT * FROM expected)"), [], |row| row.get(0)).unwrap();
            assert!(
                equal,
                "materialized placements match completed selection inputs"
            );
            let fill = brokk_bifrost_analysis::analyzer::store::rust_selected_units_fill_sql();
            let units_select = fill
                .split_once("INSERT INTO temp.selected_rust_unit_summaries\n")
                .unwrap()
                .1
                .split_once(';')
                .unwrap()
                .0;
            let equal: bool = conn.query_row(&format!(
                "WITH expected AS ({units_select}) SELECT NOT EXISTS(SELECT * FROM expected EXCEPT SELECT * FROM selected_rust_unit_summaries) AND NOT EXISTS(SELECT * FROM selected_rust_unit_summaries EXCEPT SELECT * FROM expected)"), [], |row| row.get(0)).unwrap();
            assert!(equal, "selected units match the original live predicate");
            let complete_contexts: bool = conn.query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM main.resolution_unit_summary_versions AS v JOIN main.rust_resolution_unit_summary_versions AS r USING(workspace_id,lang,generation,unit_key,valid_from,summary_id) LEFT JOIN main.rust_resolution_unit_summary_contexts AS c USING(summary_id) WHERE c.summary_id IS NULL)", [], |row| row.get(0)).unwrap();
            assert!(
                complete_contexts,
                "published route owners have their context rows"
            );
            let (roots, pairs): (i64, i64) = conn.query_row(
                "SELECT (SELECT count(*) FROM selected_rust_unit_summaries), count(*) FROM selected_rust_unit_closure", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
            assert!(
                pairs > roots,
                "fixture must exercise workspace dependency reachability"
            );
        }
        // Statistics installation writes main, so plan against the fixture's
        // writer after exercising the real read-only selection lifecycle.
        let conn = store.conn.lock().unwrap();
        prepare_pin_context(&conn);
        conn.execute_batch(
            "DELETE FROM temp.selected_resolution_mounts;
                            DELETE FROM temp.selected_rust_transient_placement_attributes;
DELETE FROM temp.selected_resolution_transient_placements;
                            DELETE FROM temp.selected_rust_unit_closure;
                            DELETE FROM temp.selected_rust_unit_summaries;
                            DELETE FROM temp.selected_workspace_revisions;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO temp.selected_workspace_revisions
                      SELECT workspace_id,lang,generation,revision FROM workspace_heads
                      WHERE workspace_id=?1 AND lang='rust'",
            [workspace.as_str()],
        )
        .unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        conn.execute_batch("INSERT INTO temp.selected_resolution_mounts(
                             mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path)
                           SELECT row_number() OVER (ORDER BY rel_path),blob_id,'rust','rust',rel_path
                           FROM (SELECT DISTINCT blob_id,rel_path FROM selected_rust_unit_members);").unwrap();
        conn.execute_batch(SELECTED_MODULE_PLACEMENTS_FILL_SQL)
            .unwrap();
        let (blob, key): (i64, Vec<u8>) = conn.query_row(
            "SELECT placement_blob,unit_key FROM selected_rust_container_placements WHERE container_path='crate'", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
        conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::GAP_CANDIDATE_SITES_SCHEMA_SQL).unwrap();
        let (topology, summary): (i64, i64) = conn
            .query_row(
                "SELECT topology_id,summary_id FROM selected_rust_unit_summaries WHERE unit_key=?1",
                [&key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for shape in ["type", "value", "macro", "root"] {
                let mut pin = pinned(&format!("rust_point_targets_{shape}"));
                pin.params[0] = Value::Integer(topology);
                pin.params[4] = Value::Integer(topology);
                let plan = explain_pin(&conn, &pin);
                for (alias, index) in [
                    ("owner", "selected_rust_unit_summaries_topology"),
                    ("dependency", "selected_rust_unit_summaries_key"),
                ] {
                    assert!(
                        plan.iter()
                            .filter(
                                |row| row.contains(&format!("SEARCH {alias} USING INDEX {index}"))
                            )
                            .count()
                            >= 5,
                        "{state} {shape}: every recursive arm seeks {alias}: {plan:?}"
                    );
                }
                assert!(
                    plan.iter().all(|row| !row.contains("AUTOMATIC")),
                    "{state} {shape}: {plan:?}"
                );
            }
            for (name, params, index) in [
                (
                    "rust_point_access_memberships",
                    vec![Value::Blob(key.clone()), Value::Integer(blob)],
                    "selected_rust_unit_closure_summary",
                ),
                (
                    "rust_point_modules",
                    vec![Value::Integer(summary)],
                    "selected_rust_unit_closure_summary",
                ),
                (
                    "rust_scope_closure_mounts",
                    vec![Value::Text(
                        serde_json::to_string(&vec![
                            brokk_bifrost_analysis::analyzer::store::resolution_lexical::hex_digest(
                                key.clone().try_into().unwrap(),
                            ),
                        ])
                        .unwrap(),
                    )],
                    "selected_rust_unit_closure_summary",
                ),
                (
                    "rust_point_crate",
                    vec![Value::Blob(key.clone())],
                    "selected_rust_unit_summaries_key",
                ),
                (
                    "rust_point_file_crates",
                    vec![Value::Integer(blob), Value::Text("src/lib.rs".into())],
                    "selected_rust_unit_summaries_summary",
                ),
                (
                    "rust_graph_crates_reaching",
                    vec![Value::Blob(key.clone())],
                    "selected_rust_unit_closure_summary",
                ),
            ] {
                let mut pin = pinned(name);
                pin.params = params;
                let plan = explain_pin(&conn, &pin);
                if name == "rust_point_modules" {
                    assert!(
                        plan.iter().any(|row| row.contains(
                            "SEARCH cargo USING INDEX selected_rust_unit_summaries_workspace"
                        )),
                        "{state} {name}: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|row| row.contains("SEARCH cargo_context")
                            && (row.contains("summary_id=?")
                                || row.contains("INTEGER PRIMARY KEY (rowid=?)"))),
                        "{state} {name}: {plan:?}"
                    );
                    assert!(
                        plan.iter().all(|row| !row.contains("SCAN cargo_context")),
                        "{state} {name}: {plan:?}"
                    );
                }
                assert!(
                    plan.iter()
                        .any(|row| row.contains("SEARCH") && row.contains(index)),
                    "{state} {name}: {plan:?}"
                );
                assert!(
                    plan.iter()
                        .all(|row| !row.contains("AUTOMATIC") && !row.contains("RECURSIVE STEP")),
                    "{state} {name}: {plan:?}"
                );
            }
            for name in [
                "rust_point_access_placements",
                "rust_point_access_reference_placements",
                "rust_point_module_placements",
            ] {
                let mut pin = pinned(name);
                pin.params = if name == "rust_point_module_placements" {
                    vec![Value::Integer(blob), Value::Text("crate".into())]
                } else {
                    vec![Value::Blob(key.clone()), Value::Integer(blob), Value::Null]
                };
                let plan = explain_pin(&conn, &pin);
                assert!(
                    plan.iter().any(|row| row.contains("SEARCH")
                        && row.contains("resolution_unit_summary_members_blob (blob_id=?")),
                    "{state} {name} must seek the blob: {plan:?}"
                );
                assert!(
                    plan.iter().all(|row| !row.contains("AUTOMATIC")
                        && !row.starts_with("SCAN placement")
                        && !row.contains("SCAN mount")),
                    "{state} {name}: {plan:?}"
                );
                if name == "rust_point_access_placements" {
                    let seek = plan
                        .iter()
                        .position(|row| {
                            row.contains("resolution_unit_summary_members_blob (blob_id=?")
                        })
                        .unwrap();
                    let graph = plan
                        .iter()
                        .position(|row| {
                            row.contains(
                                "SEARCH graph USING INDEX selected_rust_unit_closure_topology",
                            )
                        })
                        .unwrap();
                    assert!(
                        seek < graph,
                        "{state} seek placements before the dependency join: {plan:?}"
                    );
                }
            }
            let plan = explain_pin(&conn, &pinned("rust_reverse_gap_candidate_sites"));
            assert!(
                plan.iter().any(|row| row.contains(
                    "SEARCH host_owner USING INDEX selected_rust_unit_summaries_topology (topology_id=?)"
                )) && plan.iter().any(|row| {
                    row.starts_with("SEARCH p USING COVERING INDEX selected_resolution_transient_placements_")
                        && row.contains("(summary_id=?")
                }) && plan.iter().all(|row| !row.starts_with("SCAN p ")),
                "{state} reverse target hosts must seek owners by topology and placements by summary: {plan:?}"
            );
        }
    }

    /// A first persisted build leaves the store with planner statistics, and a
    /// second build of the same unchanged workspace does not recompute them.
    ///
    /// The sentinel is how "did not recompute" is observed: `ANALYZE` rewrites
    /// `sqlite_stat1` wholesale, so a row naming no real table survives exactly
    /// when the second build skipped the refresh.
    #[test]
    fn a_persisted_build_analyzes_once_and_a_no_op_build_does_not_repeat_it() {
        let _guard = statistics_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), "pub fn widget() -> u32 { 1 }\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "one file");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));

        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        let statistics = Connection::open(&db_path).unwrap();
        assert!(
            planner_statistics_row_count(&statistics).unwrap() > 0,
            "the first persisted build must leave planner statistics behind"
        );
        statistics
            .execute(
                "INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES('zzz_3016_sentinel', NULL, '1')",
                [],
            )
            .unwrap();
        drop(statistics);

        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should rebuild");
        drop(workspace);

        let statistics = Connection::open(&db_path).unwrap();
        let sentinel: i64 = statistics
            .query_row(
                "SELECT count(*) FROM sqlite_stat1 WHERE tbl = 'zzz_3016_sentinel'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            sentinel, 1,
            "a build that persisted nothing new must not re-run ANALYZE"
        );
    }

    /// The end-to-end shape of the repair: a workspace built with the switch
    /// off carries no statistics, and the next open of that store -- with the
    /// switch cleared -- gives it some.
    #[test]
    #[hardwon(
        "d78f9a16030c: disabled build-time analysis left later opens without planner statistics"
    )]
    fn a_build_with_the_switch_off_is_repaired_at_the_next_open() {
        let _guard = statistics_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), "pub fn widget() -> u32 { 1 }\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "one file");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));

        // SAFETY: the lock above serializes every test that reads or writes
        // this variable, and no other thread in this binary reads it.
        unsafe { std::env::set_var(STORE_STATISTICS_ENV, "off") };
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);
        unsafe { std::env::remove_var(STORE_STATISTICS_ENV) };

        let statistics = Connection::open(&db_path).unwrap();
        assert_eq!(
            planner_statistics_row_count(&statistics).unwrap(),
            0,
            "the build must have left this store without statistics"
        );
        drop(statistics);

        let repairs = planner_statistics_repairs();
        let store = AnalyzerStore::open_persistent(&db_path).unwrap();
        assert_eq!(
            planner_statistics_repairs(),
            repairs + 1,
            "reopening the store must repair what the switch suppressed"
        );
        assert!(
            store.planner_statistics_rows().unwrap() > 0,
            "and must leave real statistics behind"
        );
    }
}
