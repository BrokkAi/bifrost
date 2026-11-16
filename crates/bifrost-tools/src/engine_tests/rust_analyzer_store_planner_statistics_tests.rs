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
    /// The original every-mount placement alignment: the fill's SELECT before #11618,
    /// plus the unplaced exclusion every reader applied. It is the oracle the
    /// `selected_rust_container_placements` view is compared against; SQL text
    /// is a value, not source syntax.
    const VIEW: &str = "
SELECT mount_ordinal, summary_id, container_path, member_ordinal, scope_ordinal, module_declaration
FROM selected_rust_container_placements";

    const ORACLE: &str = "
SELECT mount.mount_ordinal, members.summary_id,
       CASE placement.container_path WHEN '' THEN 'crate' ELSE placement.container_path END AS container_path,
       members.member_ordinal, scope.ordinal AS scope_ordinal, scope.declaration_id AS module_declaration
FROM selected_resolution_mounts AS mount
CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id=mount.blob_id
CROSS JOIN selected_workspace_file_versions AS file
 ON file.lang=mount.storage_language AND file.rel_path=mount.persisted_relative_path
CROSS JOIN blobs AS base ON base.lang=file.lang AND base.blob_oid=file.blob_oid
 AND base.parse_variant=x''
CROSS JOIN main.resolution_unit_summary_members AS members
 ON members.rel_path=mount.persisted_relative_path
CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=members.summary_id
CROSS JOIN main.resolution_unit_summary_placements AS placement
 ON placement.summary_id=members.summary_id AND placement.member_ordinal=members.member_ordinal
WHERE mount.storage_language='rust' AND placement.scope_surface_ordinal IS NOT NULL
 AND EXISTS(SELECT 1 FROM temp.selected_unit_member_blobs AS attachment
            WHERE attachment.summary_id=members.summary_id
              AND attachment.member_ordinal=members.member_ordinal
              AND attachment.blob_id=base.id)
 AND NOT EXISTS(SELECT 1 FROM temp.selected_rust_unplaced_placements AS unplaced
                WHERE unplaced.summary_id=placement.summary_id
                  AND unplaced.container_path=placement.container_path
                  AND unplaced.member_ordinal=placement.member_ordinal)
 AND EXISTS (
 WITH RECURSIVE aligned(old_scope,new_scope) AS (
  SELECT (SELECT scope_id.dense_id FROM temp.surface_dense AS scope_id
          WHERE scope_id.blob_id=base.id AND scope_id.id_space=7
            AND scope_id.surface_ordinal=placement.scope_surface_ordinal),scope.ordinal
  UNION ALL
  SELECT old.parent_ordinal,new.parent_ordinal FROM aligned
  CROSS JOIN source_rust_module_scopes AS old ON old.blob_id=base.id AND old.ordinal=aligned.old_scope
  CROSS JOIN source_rust_module_scopes AS new ON new.blob_id=mount.blob_id AND new.ordinal=aligned.new_scope
  WHERE old.module_name=new.module_name AND old.parent_ordinal IS NOT NULL AND new.parent_ordinal IS NOT NULL
 ) SELECT 1 FROM aligned WHERE old_scope=0 AND new_scope=0)";

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::gitblob::test_repo::commit_all;

    use brokk_bifrost_core::gitblob::test_repo::init_repo;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::rust_tests_test_support::statistics_env_lock;

    #[test]
    fn selected_added_edge_target_reader_seeks_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open planner store");
            let conn = store.conn.lock().expect("store mutex");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin(
                &conn,
                &pinned("rust_selected_added_edge_target"),
            );
            assert!(
                plan.iter().any(|step| {
                    step.contains("selected_rust_added_edges_target_path (target_path=?)")
                }),
                "{state} added-edge target lookup must seek target_path: {plan:?}"
            );
        }
    }
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
                brokk_bifrost_analysis::analyzer::store::sealed_families::fixture_rows(conn, |conn| {
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
            // Compare the placements every reader sees (the changed-mount table
            // plus the persisted arm for unchanged mounts) to the original live
            // SELECT over every selected mount, including aligned inline scopes
            // and minus the unplaced set. SQL text is a value, not source syntax.
            let equal: bool = conn.query_row(&format!(
                "WITH expected AS ({ORACLE}), actual AS ({VIEW}) SELECT NOT EXISTS(SELECT * FROM expected EXCEPT SELECT * FROM actual) AND NOT EXISTS(SELECT * FROM actual EXCEPT SELECT * FROM expected)"), [], |row| row.get(0)).unwrap();
            assert!(
                equal,
                "selected placements match the original every-mount alignment"
            );
            let fill = brokk_bifrost_analysis::analyzer::store::rust_selected_units_fill_sql();
            let units_select = fill
                .split_once(
                    brokk_bifrost_analysis::analyzer::store::rust_selected_units_insert_marker(),
                )
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
        brokk_bifrost_analysis::analyzer::store::clear_selected_rust_units_for_test(&conn).unwrap();
        conn.execute_batch(
            "DELETE FROM temp.selected_resolution_mounts;
                            DELETE FROM temp.selected_rust_transient_placement_attributes;
DELETE FROM temp.selected_resolution_transient_placements;
                            DELETE FROM temp.selected_rust_unit_closure;
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
            // The added-edge statement of the fill (#11682) reads only the changed
            // declaring files: every table it reaches is a keyed seek, and no
            // automatic index is built over persisted rows.
            let added = SELECTED_MODULE_PLACEMENTS_FILL_SQL
                .split_once("INSERT INTO temp.selected_rust_added_edges\n")
                .unwrap()
                .1
                .split_once(";\n")
                .unwrap()
                .0;
            let plan = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN INSERT INTO temp.selected_rust_added_edges\n{added}"
                ))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            eprintln!("{state} added-edge fill plan: {plan:#?}");
            assert!(
                plan.iter().any(|row| row.contains(
                    "SEARCH member USING COVERING INDEX resolution_unit_summary_members_path (rel_path=?"
                )),
                "{state} the added-edge fill must seek the changed files' members by path: {plan:?}"
            );
            // Automatic indexes are allowed over the fill's own materialized
            // CTEs (bounded by the changed files), never over persisted rows.
            assert!(
                plan.iter()
                    .filter(|row| row.contains("AUTOMATIC"))
                    .all(|row| [
                        "scope",
                        "persisted",
                        "selected",
                        "edge_raw",
                        "dirs",
                        "roots",
                        "below"
                    ]
                    .iter()
                    .any(|alias| row.contains(&format!("SEARCH {alias} USING AUTOMATIC")))),
                "{state} the added-edge fill must not build an automatic index over persisted rows: {plan:?}"
            );
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
                    &["selected_rust_unit_closure_summary"][..],
                ),
                (
                    "rust_point_modules",
                    vec![Value::Integer(summary)],
                    &["selected_rust_unit_closure_summary"][..],
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
                    &["selected_rust_unit_closure_summary"][..],
                ),
                (
                    "rust_point_crate",
                    vec![Value::Blob(key.clone())],
                    &["selected_rust_unit_summaries_key"][..],
                ),
                (
                    "rust_point_file_crates",
                    vec![Value::Integer(blob), Value::Text("src/lib.rs".into())],
                    &["selected_rust_unit_summaries_summary"][..],
                ),
                (
                    "rust_graph_crates_reaching",
                    vec![Value::Blob(key.clone())],
                    // Either bounded closure seek is acceptable: the (root, summary) index, or
                    // the (summary, root) index that the #11904 impl-children gap arm added (#12169).
                    &[
                        "selected_rust_unit_closure_summary",
                        "selected_rust_unit_closure_dependents",
                    ][..],
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
                    plan.iter().any(|row| row.contains("SEARCH")
                        && index.iter().any(|index| row.contains(index))),
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
                // #11519 moved the placement view's member authority to
                // temp.selected_unit_member_blobs. Its readers now reach a
                // member through the (summary_id, member_ordinal) primary key
                // or the rel_path-leading index, both bounded keyed seeks.
                let membership_seek = |row: &str| {
                    row.contains("resolution_unit_summary_members_path (rel_path=?")
                        || row.contains(
                            "SEARCH members USING PRIMARY KEY (summary_id=? AND member_ordinal=?)",
                        )
                };
                assert!(
                    plan.iter().any(|row| membership_seek(row)),
                    "{state} {name} must seek summary membership by a key: {plan:?}"
                );
                assert!(
                    plan.iter().all(|row| !row.contains("AUTOMATIC")
                        && !row.starts_with("SCAN placement")
                        && !row.contains("SCAN mount")),
                    "{state} {name}: {plan:?}"
                );
                if name == "rust_point_access_placements" {
                    let seek = plan.iter().position(|row| membership_seek(row)).unwrap();
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
                    // #11618: the placement view reads persisted placements of
                    // an unchanged mount, reached through the members of the
                    // owner summary.
                    row.starts_with("SEARCH members USING PRIMARY KEY (summary_id=?)")
                }) && plan.iter().all(|row| {
                    !row.starts_with("SCAN p ")
                        && !row.starts_with("SCAN placement")
                        && !row.starts_with("SCAN members")
                        && !row.starts_with("SCAN mount")
                        && !row.starts_with("SCAN inactive")
                }),
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

    /// The selected placement fill does work in the size of the changed edges,
    /// not of the workspace (#11546, #11618). The fixture removes one declaring
    /// file, `app/src/lib.rs`, from a workspace that also holds `noise`
    /// unrelated crates; the SQLite virtual-machine steps of the aligned
    /// placement pass (changed mounts only), the unplacing worklist, its delete
    /// and the attribute pass must be the same for 12 and 24 of them.
    #[test]
    #[hardwon("#11546: the unplacing worklist must follow the changed edges, never the workspace")]
    fn selected_placement_unplacing_work_follows_the_changed_edges_not_the_workspace() {
        use brokk_bifrost_analysis::CancellationToken;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
            SelectedResolutionOverlayMask,
        };
        use brokk_bifrost_analysis::inline_project::InlineTestProject;
        use rusqlite::StatementStatus;
        use rusqlite::fallible_iterator::FallibleIterator;

        // Fill statements in file order: 0-1 clear the transient tables, 2 aligns
        // the placements of the changed mounts (unchanged mounts are served from
        // the persisted placements by the selected_rust_container_placements
        // view), 3-4 clear and fill the unplaced table (the worklist), 5 deletes
        // the unplaced rows from the aligned ones, 6 derives the attribute rows.
        // 7-8 clear and fill added edges; 9-10 clear and fill overlay gaps.
        let mut unplacing_steps = Vec::new();
        let mut reader_steps = Vec::new();
        for noise in [12_usize, 24] {
            let members = std::iter::once("app".to_owned())
                .chain((0..noise).map(|index| format!("noise{index}")))
                .map(|name| format!("'{name}'"))
                .collect::<Vec<_>>()
                .join(",");
            let mut project = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    format!("[workspace]\nmembers=[{members}]\nresolver='2'\n"),
                )
                .file(
                    "app/Cargo.toml",
                    "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file("app/src/lib.rs", "pub mod api; pub mod caller;\n")
                .file("app/src/api.rs", "pub fn target() {}\n")
                .file(
                    "app/src/caller.rs",
                    "pub fn caller() { crate::api::target(); }\n",
                );
            for index in 0..noise {
                project = project
                    .file(
                        format!("noise{index}/Cargo.toml"),
                        format!(
                            "[package]\nname='noise{index}'\nversion='0.1.0'\nedition='2021'\n"
                        ),
                    )
                    .file(
                        format!("noise{index}/src/lib.rs"),
                        "pub mod left; pub mod right;\n",
                    )
                    .file(
                        format!("noise{index}/src/left.rs"),
                        "pub mod deep; pub fn left() {}\n",
                    )
                    .file(
                        format!("noise{index}/src/left/deep.rs"),
                        "pub fn deep() {}\n",
                    )
                    .file(
                        format!("noise{index}/src/right.rs"),
                        "pub fn right() { crate::left::left(); }\n",
                    );
            }
            let project = project.build();
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
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &[SelectedResolutionLanguage::new("rust", Language::Rust)],
                    &[SelectedResolutionOverlayMask::removal(
                        "rust",
                        "app/src/lib.rs",
                    )],
                    &CancellationToken::default(),
                )
                .unwrap()
            else {
                panic!("complete selection");
            };
            let conn = selection.connection();
            // The selection already ran the fill once. Run it again statement by
            // statement to read each statement's step count.
            let mut steps = Vec::new();
            let mut batch = rusqlite::Batch::new(conn, SELECTED_MODULE_PLACEMENTS_FILL_SQL);
            while let Some(mut statement) = batch.next().unwrap() {
                statement.execute([]).unwrap();
                steps.push(statement.get_status(StatementStatus::VmStep));
            }
            eprintln!("noise={noise} fill statement vm steps: {steps:?}");
            assert_eq!(steps.len(), 11, "fill statements: {steps:?}");
            unplacing_steps.push((steps[2], steps[4], steps[5], steps[6], steps[8]));
            // A reader of an unchanged mount (an unrelated crate's file) pays for
            // that mount, not for the number of mounts: the view serves it from
            // the persisted placements by keyed seeks.
            let mut reader = conn
                .prepare(
                    "SELECT count(*) FROM selected_rust_container_placements
                     WHERE mount_ordinal=(SELECT mount_ordinal FROM selected_resolution_mounts
                                          WHERE storage_language='rust'
                                            AND persisted_relative_path='noise0/src/left.rs')",
                )
                .unwrap();
            let rows: i64 = reader.query_row([], |row| row.get(0)).unwrap();
            assert!(
                rows > 0,
                "noise={noise}: the unchanged mount has placements"
            );
            reader_steps.push(reader.get_status(StatementStatus::VmStep));
            eprintln!(
                "noise={noise} per-mount reader vm steps: {:?}",
                reader_steps.last()
            );
            // Removing the declaring file unplaces it and everything it declared,
            // in the one app summary and nowhere else.
            let mut unplaced: Vec<(i64, String)> = conn
                .prepare(
                    "SELECT summary_id, container_path FROM temp.selected_rust_unplaced_placements ORDER BY 2",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let summaries: std::collections::BTreeSet<i64> =
                unplaced.iter().map(|(summary, _)| *summary).collect();
            assert_eq!(summaries.len(), 1, "noise={noise}: {unplaced:?}");
            unplaced.sort();
            let containers: Vec<&str> = unplaced.iter().map(|(_, path)| path.as_str()).collect();
            assert_eq!(
                containers,
                ["", "crate::api", "crate::caller"],
                "noise={noise}"
            );
            // The gap relation projects one row per unplaced placement, keyed by module.
            let mut gaps: Vec<(String, String)> = conn
                .prepare(
                    "SELECT subject, json_extract(detail, '$.path') FROM temp.selected_rust_unplaced_gaps ORDER BY 1",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            gaps.sort();
            assert_eq!(
                gaps,
                [
                    ("crate".to_owned(), "app/src/lib.rs".to_owned()),
                    ("crate::api".to_owned(), "app/src/api.rs".to_owned()),
                    ("crate::caller".to_owned(), "app/src/caller.rs".to_owned()),
                ],
                "noise={noise}"
            );
        }
        assert_eq!(
            unplacing_steps[0], unplacing_steps[1],
            "aligned, unplacing, delete or attribute work grew with the workspace: {unplacing_steps:?}"
        );
        assert_eq!(
            reader_steps[0], reader_steps[1],
            "the per-mount reader's work grew with the workspace: {reader_steps:?}"
        );
    }
    /// The placements every reader sees are the original every-mount alignment,
    /// for unchanged mounts (persisted scope plus the inactive-placement siblings,
    /// by a keyed seek) and for a changed mount (the fill's aligned rows) alike
    /// (#11618). The fixture holds every shape the persisted walk records as an
    /// inactive placement: cfg alternatives, nested alternatives, a disabled
    /// feature, an unconditional duplicate (no placement), a macro-gated copy
    /// (activation -1), a chain past the walk's depth cap, and one file mounted
    /// at two module paths.
    #[test]
    #[hardwon(
        "#11618: unchanged mounts lost the sibling scopes of cfg alternatives when the alignment moved off them"
    )]
    fn selected_placements_of_unchanged_and_changed_mounts_match_the_every_mount_alignment() {
        // Members activate every declared feature (#12164), so x stays undeclared.
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL;
        use brokk_bifrost_analysis::inline_project::InlineTestProject;
        use rusqlite::fallible_iterator::FallibleIterator;

        let mut deep_open = String::new();
        let mut deep_close = String::new();
        for index in 0..258 {
            deep_open.push_str(&format!("pub mod m{index} {{ "));
            deep_close.push_str("} ");
        }
        let lib = format!(
            concat!(
                "#[cfg(unix)] pub mod dup {{ pub fn f() {{}} }}\n",
                "#[cfg(not(unix))] pub mod dup {{ pub fn g() {{}} }}\n",
                "#[cfg(unix)] pub mod nest {{ pub mod inner {{ pub fn a() {{}} }} }}\n",
                "#[cfg(not(unix))] pub mod nest {{ pub mod inner {{ pub fn b() {{}} }} }}\n",
                "#[cfg(unix)] pub mod u {{ pub fn f() {{}} }}\n",
                "#[cfg(not(unix))] pub mod u {{ pub fn g() {{}} }}\n",
                "#[cfg(feature = \"x\")] pub mod u {{ pub fn h() {{}} }}\n",
                "pub mod twice {{ pub fn t1() {{}} }}\n",
                "pub mod twice {{ pub fn t2() {{}} }}\n",
                "pub mod um {{ pub fn real() {{}} }}\n",
                "mystery! {{ pub mod um {{ pub fn gated() {{}} }} }}\n",
                "#[cfg(unix)] pub mod deep {{ {open}pub fn leaf() {{}}{close} }}\n",
                "#[cfg(not(unix))] pub mod deep {{ {open}pub fn leaf2() {{}}{close} }}\n",
                "pub mod a;\n",
                "#[path = \"a.rs\"] pub mod b;\n",
                "#[cfg(unix)] #[path = \"c.rs\"] pub mod c1;\n",
                "#[cfg(not(unix))] #[path = \"c.rs\"] pub mod c2;\n",
            ),
            open = deep_open,
            close = deep_close
        );
        let alternatives = "#[cfg(unix)] pub mod d { pub fn x() {} }\n#[cfg(not(unix))] pub mod d { pub fn y() {} }\npub mod inner { pub fn z() {} }\n";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='siblings'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", lib)
            .file("src/a.rs", alternatives)
            // The replacement of src/a.rs: the same scopes under other bytes. It is
            // not mounted, so it is only a persisted blob to mount in its place.
            .file("src/a_replacement.rs", format!("{alternatives}pub mod added;\ninclude!(\"added.rs\");\npub mod host {{ include!(\"included.rs\"); }}\n#[cfg(all())] pub mod activated;\n"))
            .file("src/added.rs", "pub fn added() {}\n")
            .file("src/included.rs", "include!(\"nested.rs\");\n")
            .file("src/nested.rs", "pub fn nested() {}\n")
            .file("src/a/added.rs", "pub fn target() {}\n")
            .file("src/a/activated.rs", "pub fn active() {}\n")
            .file(
                "src/c.rs",
                "#[cfg(unix)] pub mod e { pub fn x() {} }\n#[cfg(not(unix))] pub mod e { pub fn y() {} }\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        let workspace_id: String = conn
            .query_row(
                "SELECT workspace_id FROM workspace_heads WHERE lang='rust'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        prepare_pin_context(&conn);
        let activation_gaps: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_resolution_unit_summary_inactive_placements WHERE activation=-1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            activation_gaps > 0,
            "the macro-gated and duplicate copies are persisted as activation -1"
        );
        let replacement_blob: i64 = conn
            .query_row(
                "SELECT blob.id FROM blobs AS blob
                 JOIN workspace_file_versions AS file
                   ON file.lang=blob.lang AND file.blob_oid=blob.blob_oid
                 WHERE file.lang='rust' AND file.rel_path='src/a_replacement.rs' AND blob.parse_variant=x''
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let fill = |replaced: Option<&str>| -> i32 {
            conn.execute_batch(
                "DELETE FROM temp.selected_resolution_mounts;
                 DELETE FROM temp.selected_resolution_overlay_masks;
                 DELETE FROM temp.selected_rust_transient_placement_attributes;
                 DELETE FROM temp.selected_resolution_transient_placements;
                 DELETE FROM temp.selected_rust_unit_closure;
                 DELETE FROM temp.selected_workspace_revisions;",
            )
            .unwrap();
            brokk_bifrost_analysis::analyzer::store::clear_selected_rust_units_for_test(&conn)
                .unwrap();
            conn.execute(
                "INSERT INTO temp.selected_workspace_revisions
                 SELECT workspace_id,lang,generation,revision FROM workspace_heads
                 WHERE workspace_id=?1 AND lang='rust'",
                [&workspace_id],
            )
            .unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            conn.execute(
                "INSERT INTO temp.selected_resolution_mounts(
                  mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path)
                 SELECT row_number() OVER (ORDER BY rel_path),
                        CASE WHEN rel_path=?1 THEN ?2 ELSE blob_id END,'rust','rust',rel_path
                 FROM (SELECT DISTINCT blob_id,rel_path FROM selected_rust_unit_members)",
                rusqlite::params![replaced, replacement_blob],
            )
            .unwrap();
            if let Some(path) = replaced {
                conn.execute(
                    "INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent)
                     VALUES('rust',?1,'replacement')",
                    [path],
                )
                .unwrap();
            }
            // Statement 2 of the fill is the aligned pass over the changed mounts.
            let mut steps = 0;
            let mut batch = rusqlite::Batch::new(&conn, SELECTED_MODULE_PLACEMENTS_FILL_SQL);
            let mut index = 0;
            while let Some(mut statement) = batch.next().unwrap() {
                statement.execute([]).unwrap();
                if index == 2 {
                    steps = statement.get_status(rusqlite::StatementStatus::VmStep);
                }
                index += 1;
            }
            steps
        };
        let unchanged_steps = fill(None);
        let changed_steps = fill(Some("src/a.rs"));
        eprintln!("aligned pass vm steps: no changed mount {unchanged_steps}, one {changed_steps}");
        assert!(
            changed_steps > unchanged_steps,
            "the aligned pass follows the changed mounts: {unchanged_steps} vs {changed_steps}"
        );
        for replaced in [None, Some("src/a.rs")] {
            fill(replaced);
            let equal: bool = conn.query_row(&format!(
                "WITH expected AS ({ORACLE}), actual AS ({VIEW}) SELECT NOT EXISTS(SELECT * FROM expected EXCEPT SELECT * FROM actual) AND NOT EXISTS(SELECT * FROM actual EXCEPT SELECT * FROM expected)"), [], |row| row.get(0)).unwrap();
            assert!(
                equal,
                "{replaced:?}: selected placements match the every-mount alignment"
            );
            let siblings: std::collections::BTreeSet<String> = conn
                .prepare(
                    "SELECT container_path FROM selected_rust_container_placements
                     GROUP BY mount_ordinal, summary_id, container_path, member_ordinal
                     HAVING count(*) > 1",
                )
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            for expected in [
                "crate::dup",
                "crate::nest",
                "crate::nest::inner",
                "crate::u",
                "crate::um",
                "crate::a::d",
                "crate::b::d",
                // Only the host-active cfg alternative has a module path.
                if cfg!(unix) {
                    "crate::c1::e"
                } else {
                    "crate::c2::e"
                },
            ] {
                assert!(
                    siblings.contains(expected),
                    "{replaced:?}: {expected} holds its sibling scopes: {siblings:?}"
                );
            }
            assert!(
                !siblings.contains("crate::twice"),
                "{replaced:?}: an unconditional duplicate has no placement: {siblings:?}"
            );
            assert!(
                siblings
                    .iter()
                    .filter(|path| path.starts_with("crate::deep::"))
                    .count()
                    > 200,
                "{replaced:?}: the chain below the depth cap keeps its siblings"
            );
        }

        // Plans of the reader shapes, in both statistics states: the sibling arm
        // seeks the inactive placements by their key and the fill's aligned pass
        // is driven by the overlay masks, never by every mount.
        fill(None);
        let blob: i64 = conn
            .query_row(
                "SELECT placement_blob FROM selected_rust_container_placements WHERE container_path='crate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let aligned_pass = SELECTED_MODULE_PLACEMENTS_FILL_SQL
            .split_once("INSERT INTO temp.selected_resolution_transient_placements\n")
            .unwrap()
            .1
            .split_once(';')
            .unwrap()
            .0;
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (shape, sql) in [
                (
                    "by mount",
                    "SELECT scope_ordinal FROM selected_rust_container_placements WHERE mount_ordinal=1".to_owned(),
                ),
                (
                    "by placement blob and module",
                    format!("SELECT scope_ordinal, module_declaration FROM selected_rust_container_placements WHERE placement_blob={blob} AND container_path='crate::dup'"),
                ),
            ] {
                let plan = explain_plan(&conn, &sql);
                assert!(
                    plan.iter().any(|row| row.starts_with("SEARCH inactive")
                        && row.contains("rust_resolution_unit_summary_inactive_placements")
                        && row.contains("summary_id=? AND module_path=? AND input_file_ordinal=?")),
                    "{state} {shape}: the sibling arm must seek the inactive placements by their key: {plan:?}"
                );
                assert!(
                    plan.iter().all(|row| !row.contains("SCAN inactive")
                        && !row.contains("AUTOMATIC")
                        && !row.contains("TEMP B-TREE")),
                    "{state} {shape}: {plan:?}"
                );
            }
            let plan = explain_plan(&conn, aligned_pass);
            assert!(
                plan.first().is_some_and(|row| row.contains(" mask USING PRIMARY KEY") || row.starts_with("SCAN mask"))
                    && plan.iter().any(|row| row.starts_with("SEARCH mount USING INDEX sqlite_autoindex_selected_resolution_mounts_2 (storage_language=? AND persisted_relative_path=?)"))
                    && plan.iter().all(|row| !row.starts_with("SCAN mount")),
                "{state}: the aligned pass must be driven by the overlay masks: {plan:?}"
            );
        }
    }

    fn explain_plan(conn: &Connection, sql: &str) -> Vec<String> {
        conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
}
