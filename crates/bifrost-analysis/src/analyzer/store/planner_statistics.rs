//! Planner statistics for the analyzer store (issue #3016).
//!
//! SQLite picks how to run each query with its query planner. Without the
//! `sqlite_stat1` table the planner works from fixed default guesses about how
//! many rows each index covers. `ANALYZE` fills `sqlite_stat1` in; nothing in
//! Bifrost used to run it, so every plan the store got was a default-guess
//! plan.
//!
//! The SQL itself lives in `brokk_bifrost_core::cache_gc`, because cache
//! garbage collection runs the same refresh from the core side and
//! `brokk-bifrost-core` must not depend on this crate. This module is the
//! analyzer store's entry point to it, plus the tooling that shows what the
//! refresh does to the query plans this repository pins.

use brokk_bifrost_core::cache_gc::{
    PlannerStatisticsRefresh, planner_statistics_describe_database, planner_statistics_row_count,
    refresh_planner_statistics,
};

use super::{AnalyzerStore, Result, StoreError};

impl AnalyzerStore {
    /// Recompute this store's query-planner statistics unconditionally.
    ///
    /// The build and garbage-collection hooks use
    /// [`Self::refresh_planner_statistics_if_stale`]; this one exists for
    /// callers that want the refresh to happen regardless, such as a benchmark
    /// measuring the same store with and without statistics.
    pub fn refresh_planner_statistics(&self) -> Result<PlannerStatisticsRefresh> {
        self.conn
            .execute(|conn| refresh_planner_statistics(conn).map_err(StoreError::new))
    }

    /// Refresh only when the stored statistics no longer describe the store.
    ///
    /// Returns `None` when nothing has been persisted or collected since the
    /// last refresh, which is what makes a repeated no-op build free.
    pub fn refresh_planner_statistics_if_stale(&self) -> Result<Option<PlannerStatisticsRefresh>> {
        self.conn.execute(|conn| {
            if planner_statistics_describe_database(conn).map_err(StoreError::new)? {
                return Ok(None);
            }
            refresh_planner_statistics(conn)
                .map(Some)
                .map_err(StoreError::new)
        })
    }

    /// How many `sqlite_stat1` rows this store carries, zero when `ANALYZE` has
    /// never run.
    pub fn planner_statistics_rows(&self) -> Result<i64> {
        self.conn
            .execute(|conn| planner_statistics_row_count(conn).map_err(StoreError::new))
    }

    /// Return this store to the state it has before its first refresh, and
    /// report how many statistics rows were removed.
    ///
    /// This is what makes a before-and-after measurement repeatable: the second
    /// run of the benchmark finds the statistics its first run wrote, and
    /// without this its "before" half would measure the "after" state. SQLite
    /// forbids dropping `sqlite_stat1`, so the rows go and `ANALYZE
    /// sqlite_schema` reloads the planner's now-empty view of them, which is
    /// the documented way to make the planner re-read that table without
    /// recomputing it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn clear_planner_statistics(&self) -> Result<i64> {
        self.conn.execute(|conn| {
            let rows = planner_statistics_row_count(conn).map_err(StoreError::new)?;
            if rows == 0 {
                return Ok(0);
            }
            conn.execute_batch("DELETE FROM sqlite_stat1; ANALYZE sqlite_schema;")
                .map_err(|error| {
                    StoreError::new(format!("clearing planner statistics: {error}"))
                })?;
            Ok(rows)
        })
    }
}

/// The pinned-query registry, and the plan dump that replays it against a
/// real store.
///
/// A "pin" here is one SQL statement whose EXPLAIN QUERY PLAN a test asserts
/// on: that it seeks a named index, that it never scans a large table, that it
/// builds no transient (`AUTOMATIC`) index and no `TEMP B-TREE` sort. Every
/// such statement in the store module is written once, here, so the tests that
/// assert on a plan and the tooling that reports a plan can never drift apart.
///
/// This is gated on `test-support` rather than compiled always because nothing
/// in the product reads it: the pin tests use it, the two ignored operator
/// tests below print it, and the benchmark's before-and-after planner
/// statistics pass (issue #3016, Milestone 3) calls
/// [`pinned_query_plans`] to say whether a repository's statistics changed any
/// pinned plan.
#[cfg(any(test, feature = "test-support"))]
pub mod pinned_plans {
    use rusqlite::types::Value;
    use rusqlite::{Connection, params_from_iter};

    use super::super::{
        AnalyzerStore, EXACT_PATH_SYMBOL_FQN_SQL, NORMALIZED_PATH_SYMBOL_FQN_SQL,
        REVERSE_IDENTIFIER_CANDIDATE_PATHS_SQL, REVERSE_IMPORT_CANDIDATE_BLOBS_SQL,
        REVERSE_TYPE_CANDIDATE_BLOBS_SQL, RUST_MODULE_IMPORT_CANDIDATE_BLOBS_SQL,
        RenderedTailMatch, Result, StoreError, WorkspaceSnapshots,
        batch_anchor_only_definition_candidate_sql, batch_component_definition_candidate_sql,
        candidate_fq_segments_sql, chunk_params, chunk_placeholders,
        direct_children_limited_candidate_sql, enclosing_declarations_for_file_sql,
        identifier_prefix_candidate_sql, limited_identifier_candidate_for_blob_sql,
        mounted_declaration_sql, parsed_blob_keys_sql, persisted_blob_mutation_cost_fallback_sql,
        point_anchor_only_definition_candidate_sql, point_component_definition_candidate_sql,
        ranges_bulk_sql, raw_unit_fq_segments_sql, read_path_parsed_blob_condition,
        search_candidate_key_set_sql, search_candidate_name_rows_sql,
        signature_metadata_for_unit_limited_sql, signature_metadata_value_columns_sql,
        stored_blob_cascade_costs_sql, sync_active_blob_oids, sync_reverse_reference_lookup_keys,
        workspace_content_package_facts_sql,
    };

    pub(crate) const OID: &str = "0123456789012345678901234567890123456789";
    pub(crate) const MEMBERSHIP: &str = "units.in_declarations = 1";

    fn text(value: &str) -> Value {
        Value::Text(value.to_string())
    }

    fn integer(value: i64) -> Value {
        Value::Integer(value)
    }

    /// One pinned query: the SQL an EXPLAIN QUERY PLAN test in this crate
    /// asserts on, plus bindings that make it prepare and plan.
    pub struct PinnedQuery {
        pub name: String,
        pub sql: String,
        pub params: Vec<Value>,
    }

    fn pin(name: impl Into<String>, sql: impl Into<String>, params: Vec<Value>) -> PinnedQuery {
        PinnedQuery {
            name: name.into(),
            sql: sql.into(),
            params,
        }
    }

    /// The one entry named `name`, for the pin test that asserts on its plan.
    ///
    /// This registry is the single source of every pinned SQL expression in
    /// the store module: the pin tests plan what it holds, and
    /// [`dump_pinned_plans_for_store`] replays the same statements against a
    /// real repository store. A second copy of the SQL in a test would let the
    /// two drift, which is what this lookup exists to prevent.
    pub fn pinned(name: &str) -> PinnedQuery {
        let mut queries = pinned_queries();
        let Some(index) = queries.iter().position(|query| query.name == name) else {
            let names = queries
                .iter()
                .map(|query| query.name.as_str())
                .collect::<Vec<_>>();
            panic!("no pinned query named {name}; the registry holds {names:?}");
        };
        queries.swap_remove(index)
    }

    /// The plan SQLite chooses for one pinned query, as its detail column.
    pub fn explain_pin(conn: &Connection, query: &PinnedQuery) -> Vec<String> {
        plan_rows(conn, query)
            .unwrap_or_else(|error| panic!("planning pinned query {}: {error}", query.name))
    }

    /// The temp tables and temp views the pinned queries read.
    ///
    /// Several pinned statements join a session-scoped temp table that the
    /// production call sites populate before they run. Without these the SQL
    /// does not even prepare, so the dump would report a preparation error
    /// instead of a plan.
    pub fn prepare_pin_context(conn: &Connection) {
        sync_active_blob_oids(conn, &[]).expect("active blob temp table");
        sync_reverse_reference_lookup_keys(
            conn,
            &["Target".to_string()].into_iter().collect(),
            &["pkg".to_string()].into_iter().collect(),
            &["Target".to_string()].into_iter().collect(),
        )
        .expect("reverse lookup temp tables");
    }

    /// Every EXPLAIN QUERY PLAN pin this crate's store module owns, as data.
    ///
    /// This is where each of those statements is written, once. The pin tests
    /// in `store/mod.rs` fetch their subject from here with [`pinned`], and the
    /// two operator dumps below replay the whole list against a real
    /// repository store and against the captured statistics. Before this
    /// registry existed the dump carried its own copy of every statement and
    /// could drift from the test that asserts on it.
    pub fn pinned_queries() -> Vec<PinnedQuery> {
        let mut queries = Vec::new();

        let metadata_columns = signature_metadata_value_columns_sql("metadata");
        queries.push(pin(
            "signature_metadata_batch_reader",
            format!(
                "SELECT keys.blob_oid, metadata.unit_key, {metadata_columns}
                 FROM blobs AS keys
                 JOIN unit_signature_metadata AS metadata ON metadata.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN (?, ?)
                 ORDER BY keys.blob_oid, metadata.unit_key, metadata.ordinal"
            ),
            vec![text("java"), text(OID), text(OID)],
        ));
        queries.push(pin(
            "signature_metadata_for_unit_limited",
            signature_metadata_for_unit_limited_sql(),
            vec![
                text(OID),
                text("java"),
                text("a.B"),
                text("1"),
                text("B"),
                text("sig"),
                text("0"),
                text("10"),
            ],
        ));
        queries.push(pin(
            "enclosing_declarations_for_file",
            enclosing_declarations_for_file_sql(),
            vec![text(OID), text("rust")],
        ));

        for (table, order_by) in [
            ("structural_fact_nodes", "node_id"),
            ("structural_fact_roles", "source_node_id, ordinal"),
            ("structural_fact_occurrence_roles", "node_id, ordinal"),
        ] {
            queries.push(pin(
                format!("structural_fact_hydration_{table}"),
                format!("SELECT * FROM {table} WHERE blob_id = ?1 ORDER BY {order_by}"),
                vec![integer(0)],
            ));
        }

        let langs = vec!["rust".to_string(), "python".to_string()];
        for (label, required) in [
            ("search_candidate_name_rows_unfiltered", None),
            (
                "search_candidate_name_rows_prefiltered",
                Some(vec![
                    vec!["valueflow".to_string()],
                    vec!["taint".to_string()],
                ]),
            ),
        ] {
            let (sql, literals) = search_candidate_name_rows_sql(&langs, required.as_deref());
            let params = langs
                .iter()
                .chain(literals.iter())
                .map(|value| text(value))
                .collect();
            queries.push(pin(label, sql, params));
        }
        queries.push(pin(
            "search_candidate_key_set",
            search_candidate_key_set_sql(1),
            vec![text("java"), text(OID), integer(0)],
        ));

        queries.push(pin(
            "read_path_parsed_blob_membership",
            parsed_blob_keys_sql(2, "", read_path_parsed_blob_condition()),
            vec![Value::Null; 4],
        ));

        let chunk = ["a".to_string(), "b".to_string()];
        queries.push(pin(
            "ranges_bulk",
            ranges_bulk_sql(&chunk_placeholders(&chunk)),
            chunk_params("rust", &chunk)
                .into_iter()
                .map(|value| match value {
                    Some(text_value) => Value::Text(text_value),
                    None => Value::Null,
                })
                .collect(),
        ));

        for (label, sql) in [
            ("exact_path_symbol_fqn", EXACT_PATH_SYMBOL_FQN_SQL),
            ("normalized_path_symbol_fqn", NORMALIZED_PATH_SYMBOL_FQN_SQL),
        ] {
            queries.push(pin(label, sql, vec![text("python"), text("pkg.service")]));
        }

        queries.push(pin(
            "workspace_snapshot_identity",
            "SELECT revision FROM workspace_heads
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3",
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                text("python"),
                integer(0),
            ],
        ));

        queries.push(pin(
            "stored_blob_cascade_costs",
            stored_blob_cascade_costs_sql(3),
            vec![
                text(OID),
                text("java"),
                text(OID),
                text("java"),
                text(OID),
                text("java"),
            ],
        ));
        queries.push(pin(
            "persisted_blob_mutation_cost_fallback",
            persisted_blob_mutation_cost_fallback_sql(),
            vec![text(OID), text("java")],
        ));

        for arity in [1usize, 16, 64, 256, 400] {
            queries.push(pin(
                format!("candidate_fq_segments_{arity}"),
                candidate_fq_segments_sql(arity),
                vec![Value::Null; arity * 4],
            ));
        }
        queries.push(pin(
            "raw_unit_fq_segments",
            raw_unit_fq_segments_sql("?, ?"),
            vec![text("java"), text(OID), text(OID)],
        ));

        queries.push(pin(
            "limited_identifier_candidate_for_blob",
            format!("{} LIMIT ?4", limited_identifier_candidate_for_blob_sql()),
            vec![text("rust"), text("Widget"), text(OID), integer(16)],
        ));
        queries.push(pin(
            "point_component_definition_candidate_exact",
            point_component_definition_candidate_sql(true, RenderedTailMatch::Exact, MEMBERSHIP),
            vec![text("java"), integer(0), text("pkg"), text("Widget")],
        ));
        queries.push(pin(
            "point_component_definition_candidate_stable",
            point_component_definition_candidate_sql(false, RenderedTailMatch::Exact, MEMBERSHIP),
            vec![text("java"), integer(0), text("pkg.Widget")],
        ));
        queries.push(pin(
            "point_anchor_only_definition_candidate",
            point_anchor_only_definition_candidate_sql(MEMBERSHIP),
            vec![text("java"), integer(0), text("pkg")],
        ));
        queries.push(pin(
            "batch_component_definition_candidate",
            batch_component_definition_candidate_sql(true, RenderedTailMatch::Exact, MEMBERSHIP),
            vec![
                text("[[0,\"pkg\",\"Widget\",0,1]]"),
                text("java"),
                integer(0),
            ],
        ));
        queries.push(pin(
            "batch_anchor_only_definition_candidate",
            batch_anchor_only_definition_candidate_sql(MEMBERSHIP),
            vec![text("[[0,\"pkg\",\"\",0,1]]"), text("java"), integer(0)],
        ));
        queries.push(pin(
            "direct_children_limited_candidate",
            direct_children_limited_candidate_sql(),
            vec![
                text(OID),
                text("scala"),
                text("app.Child"),
                integer(0),
                text("Child"),
                Value::Null,
                integer(0),
                integer(1),
            ],
        ));

        queries.push(pin(
            "mounted_declaration_scan",
            mounted_declaration_sql(),
            vec![text("csharp")],
        ));
        queries.push(pin(
            "identifier_prefix_candidate",
            identifier_prefix_candidate_sql(),
            vec![text("csharp"), text("Widget`"), text("Widgeta")],
        ));

        queries.push(pin(
            "import_statements_per_blob",
            format!(
                "SELECT {} FROM import_statements
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
                 ORDER BY ordinal",
                super::super::IMPORT_STATEMENT_COLUMNS
            ),
            vec![text(OID), text("rust")],
        ));
        for (table, value_columns) in [
            ("import_path_segments", "segment"),
            ("import_lexical_prefixes", "prefix"),
            ("import_lexical_scopes", "start_byte, end_byte"),
        ] {
            queries.push(pin(
                format!("import_child_{table}"),
                format!(
                    "SELECT keys.blob_oid, facts.ordinal, {value_columns}
                     FROM blobs AS keys
                     JOIN {table} AS facts ON facts.blob_id = keys.id
                     WHERE keys.lang = ? AND keys.blob_oid IN (?, ?)
                     ORDER BY keys.blob_oid, facts.ordinal"
                ),
                vec![text("rust"), text(OID), text(OID)],
            ));
        }

        queries.push(pin(
            "workspace_content_package_facts",
            workspace_content_package_facts_sql(2),
            vec![text("java"), text(OID), text(OID)],
        ));

        for (label, sql) in [
            (
                "reverse_import_candidate_blobs",
                REVERSE_IMPORT_CANDIDATE_BLOBS_SQL,
            ),
            (
                "reverse_type_candidate_blobs",
                REVERSE_TYPE_CANDIDATE_BLOBS_SQL,
            ),
            (
                "reverse_identifier_candidate_paths",
                REVERSE_IDENTIFIER_CANDIDATE_PATHS_SQL,
            ),
        ] {
            queries.push(pin(label, sql, vec![text("java")]));
        }
        queries.push(pin(
            "rust_module_import_candidate_blobs",
            RUST_MODULE_IMPORT_CANDIDATE_BLOBS_SQL,
            vec![text("rust"), text("semantic")],
        ));

        queries
    }

    pub(crate) fn plan_rows(
        conn: &Connection,
        query: &PinnedQuery,
    ) -> std::result::Result<Vec<String>, String> {
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {}", query.sql))
            .map_err(|error| format!("prepare: {error}"))?;
        statement
            .query_map(params_from_iter(query.params.iter()), |row| {
                row.get::<_, String>(3)
            })
            .map_err(|error| format!("bind: {error}"))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| format!("read: {error}"))
    }

    /// One pinned query's plan on the store it was asked about.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PinnedQueryPlan {
        /// The registry name of the pinned query, such as
        /// `mounted_declaration_scan`.
        pub pin: String,
        /// The `detail` column of `EXPLAIN QUERY PLAN`, one entry per plan row,
        /// in plan order.
        pub plan: Vec<String>,
    }

    /// Plan every registered pinned query against a real repository store.
    ///
    /// Call it before and after [`AnalyzerStore::refresh_planner_statistics`]
    /// and compare the two results: a pin whose plan differs is one the
    /// statistics moved, which is the plan-flip evidence issue #3016 reports
    /// per repository.
    ///
    /// The reader's revisioned workspace views are pointed at an empty
    /// selection, exactly as the operator dump does, so the plans depend only
    /// on the schema and on `sqlite_stat1` and not on which workspace happened
    /// to be current.
    pub fn pinned_query_plans(store: &AnalyzerStore) -> Result<Vec<PinnedQueryPlan>> {
        let conn = store.read_conn_for_workspace(&WorkspaceSnapshots::default())?;
        prepare_pin_context(&conn);
        pinned_queries()
            .into_iter()
            .map(|query| {
                plan_rows(&conn, &query)
                    .map(|plan| PinnedQueryPlan {
                        pin: query.name.clone(),
                        plan,
                    })
                    .map_err(|error| {
                        StoreError::new(format!("planning pinned query {}: {error}", query.name))
                    })
            })
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    use rusqlite::Connection;

    use super::super::AnalyzerStore;
    // The pinned SQL, its bindings, and the two helpers that plan it live in
    // `pinned_plans` so the benchmark can call them too; the pin tests in
    // `store/mod.rs` still reach them through this module's path, which is why
    // the three they use are re-exported rather than merely imported.
    use super::pinned_plans::{OID, pinned_queries, plan_rows};
    pub(crate) use super::pinned_plans::{explain_pin, pinned, prepare_pin_context};
    use std::sync::Arc;

    use brokk_bifrost_core::cache_gc::{
        PlannerStatisticsState, STORE_STATISTICS_ENV, planner_statistics_row_count,
        with_representative_statistics,
    };

    use crate::analyzer::workspace::WorkspaceAnalyzer;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject};
    use crate::gitblob::test_repo::{commit_all, init_repo};

    /// Dump the plan of every pinned query against a real repository store.
    ///
    /// Point `BIFROST_3016_STORE_PATH` at a `bifrost_cache.v*.db` file and run
    /// this with `--ignored --nocapture`. It prints one JSON object per line.
    /// Running it before and after `ANALYZE` on the same store, and diffing the
    /// two outputs, is how issue #3016 produced its plan-flip list.
    #[test]
    #[ignore = "operator tool: needs BIFROST_3016_STORE_PATH pointing at a real store"]
    fn dump_pinned_plans_for_store() {
        let path = PathBuf::from(
            std::env::var("BIFROST_3016_STORE_PATH")
                .expect("set BIFROST_3016_STORE_PATH to a bifrost cache database"),
        );
        let store = AnalyzerStore::open_persistent(&path).expect("open store");
        // A persistent store's writer connection belongs to the writer actor,
        // so the plans come from a pooled reader. `read_conn` also points the
        // reader's revisioned workspace views at the store's own current
        // snapshots, which is what the pinned queries read through.
        let conn = store.read_conn().expect("reader connection");
        prepare_pin_context(&conn);
        eprintln!(
            "{}",
            serde_json::json!({
                "store": path.display().to_string(),
                "sqlite_stat1_rows": planner_statistics_row_count(&conn).expect("stat1 rows"),
            })
        );
        for query in pinned_queries() {
            let record = match plan_rows(&conn, &query) {
                Ok(plan) => serde_json::json!({"pin": query.name, "plan": plan}),
                Err(error) => serde_json::json!({"pin": query.name, "error": error}),
            };
            println!("{record}");
        }
    }

    /// The same dump, but the plans come from an in-memory store carrying the
    /// statistics captured from a real one.
    ///
    /// `sqlite_stat1` is what the planner reads; the rows themselves are not.
    /// Loading a captured `sqlite_stat1` into an empty store therefore
    /// reproduces the real store's planning inputs without its data, which is
    /// what makes the pinned plans testable in CI.
    #[test]
    #[ignore = "operator tool: prints plans rather than asserting on them"]
    fn dump_pinned_plans_with_captured_statistics() {
        // An ephemeral store's own connection, not a pooled reader: readers are
        // read-only, and installing captured statistics writes `sqlite_stat1`.
        let store = AnalyzerStore::open_ephemeral().expect("open store");
        let conn = store.conn.lock().expect("store mutex");
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .expect("workspace selection views");
        prepare_pin_context(&conn);
        with_representative_statistics(&conn);
        eprintln!(
            "{}",
            serde_json::json!({
                "sqlite_stat1_rows": planner_statistics_row_count(&conn).expect("stat1 rows"),
            })
        );
        for query in pinned_queries() {
            let record = match plan_rows(&conn, &query) {
                Ok(plan) => serde_json::json!({"pin": query.name, "plan": plan}),
                Err(error) => serde_json::json!({"pin": query.name, "error": error}),
            };
            println!("{record}");
        }
    }

    /// Every registered pinned query prepares and plans in both statistics
    /// states.
    ///
    /// The pin tests each reach for one entry by name, so a registry entry
    /// whose SQL stopped preparing -- a renamed column, a dropped view --
    /// would only fail wherever it happened to be used. This runs all of them,
    /// and it is also what proves the fixture install works against the store
    /// schema rather than silently skipping every row.
    #[test]
    fn every_pinned_query_plans_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            if state == PlannerStatisticsState::Representative {
                assert!(
                    planner_statistics_row_count(&conn).expect("stat1 rows") > 0,
                    "the captured statistics must name tables this schema has"
                );
            }
            for query in pinned_queries() {
                let plan = explain_pin(&conn, &query);
                assert!(
                    !plan.is_empty(),
                    "pinned query {} planned to nothing {state}",
                    query.name
                );
            }
        }
    }

    #[test]
    fn a_fresh_store_has_no_planner_statistics() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        assert_eq!(
            planner_statistics_row_count(&conn).unwrap(),
            0,
            "a store that has never run ANALYZE must not have a sqlite_stat1 table"
        );
    }

    /// A blob and a declaration are enough to make `ANALYZE` describe the
    /// store's own write path. (`ANALYZE` writes no `sqlite_stat1` row for an
    /// empty table, so an untouched store legitimately produces almost none.)
    #[test]
    fn refreshing_planner_statistics_covers_the_store_write_path() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        {
            let conn = store.conn.lock().expect("store mutex");
            insert_one_declaration(&conn);
        }
        let evidence = store.refresh_planner_statistics().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        assert_eq!(
            evidence.stat1_rows,
            planner_statistics_row_count(&conn).unwrap(),
            "the reported row count must match what the store holds"
        );
        let analyzed: HashSet<String> = conn
            .prepare("SELECT DISTINCT tbl FROM sqlite_stat1")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        for table in ["blobs", "code_units"] {
            assert!(
                analyzed.contains(table),
                "ANALYZE must produce statistics for {table}: {analyzed:?}"
            );
        }
    }

    /// The stale check is a fixed point: a refresh makes it report current, and
    /// a store whose blob set then changes reports stale again.
    #[test]
    fn the_stale_check_tracks_the_stores_blob_set() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        {
            let conn = store.conn.lock().expect("store mutex");
            insert_one_declaration(&conn);
        }
        assert!(
            store
                .refresh_planner_statistics_if_stale()
                .unwrap()
                .is_some(),
            "a store with no statistics must refresh"
        );
        assert!(
            store
                .refresh_planner_statistics_if_stale()
                .unwrap()
                .is_none(),
            "an unchanged store must not re-analyze"
        );
        {
            let conn = store.conn.lock().expect("store mutex");
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'java')",
                [OID],
            )
            .unwrap();
        }
        assert!(
            store
                .refresh_planner_statistics_if_stale()
                .unwrap()
                .is_some(),
            "a store that gained a blob must re-analyze"
        );
        assert!(
            store
                .refresh_planner_statistics_if_stale()
                .unwrap()
                .is_none(),
            "and must then settle again"
        );
    }

    /// A first persisted build leaves the store with planner statistics, and a
    /// second build of the same unchanged workspace does not recompute them.
    ///
    /// The sentinel is how "did not recompute" is observed: `ANALYZE` rewrites
    /// `sqlite_stat1` wholesale, so a row naming no real table survives exactly
    /// when the second build skipped the refresh.
    #[test]
    fn a_persisted_build_analyzes_once_and_a_no_op_build_does_not_repeat_it() {
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

    /// `BIFROST_STORE_STATISTICS=off` leaves the store with no statistics at
    /// all, which is how a statistics-free plan is reproduced.
    ///
    /// The environment variable is process-wide, so this test sets it around
    /// one build and restores it; it does not run beside the test above.
    #[test]
    fn the_off_switch_leaves_a_persisted_build_without_statistics() {
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
            "BIFROST_STORE_STATISTICS=off must leave no sqlite_stat1 rows"
        );
    }

    /// A collection that dropped rows refreshes the statistics it invalidated.
    ///
    /// The setup makes one persisted blob genuinely unreachable: two commits,
    /// each built, then the branch is moved back to the first and the working
    /// tree is restored to the first content, so nothing in Git or on disk
    /// reaches the second blob any more.
    #[test]
    fn a_collection_that_drops_rows_refreshes_the_statistics() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = "pub fn widget() -> u32 { 1 }\n";
        let second = "pub fn widget() -> u32 { 2 }\npub fn extra() -> u32 { 3 }\n";
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();
        let repository = init_repo(&root);
        let first_commit = commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        std::fs::write(root.join("app.rs"), second).unwrap();
        commit_all(&repository, "second content");
        drop(
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should rebuild"),
        );

        let head = repository.head().unwrap();
        let branch = head.name().expect("a named branch").to_string();
        repository
            .reference(&branch, first_commit, true, "drop the second commit")
            .unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();

        let statistics = Connection::open(&db_path).unwrap();
        statistics
            .execute(
                "INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES('zzz_3016_sentinel', NULL, '1')",
                [],
            )
            .unwrap();
        drop(statistics);

        let outcome = brokk_bifrost_core::cache_gc::force_gc(&db_path, &repository, &root)
            .expect("forced collection");
        assert!(
            outcome.analyzer_dropped > 0,
            "the setup must leave the second content collectable: {outcome:?}"
        );
        let statistics = Connection::open(&db_path).unwrap();
        let sentinel: i64 = statistics
            .query_row(
                "SELECT count(*) FROM sqlite_stat1 WHERE tbl = 'zzz_3016_sentinel'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            sentinel, 0,
            "a collection that dropped {} rows must re-run ANALYZE",
            outcome.analyzer_dropped
        );
        assert!(
            planner_statistics_row_count(&statistics).unwrap() > 0,
            "and must leave real statistics behind"
        );
    }

    /// Serializes the tests that set `BIFROST_STORE_STATISTICS`, which is
    /// process-wide state.
    ///
    /// The lock is local to this module because the workspace has no shared
    /// one: `grep -rn "set_var" --include=*.rs crates tests src` finds exactly
    /// one other test that mutates the environment
    /// (`tests/suite_bench_policy/measure_policy_substrate.rs`, which sets
    /// `BIFROST_CACHE_DIR` and holds no lock at all), and there is no
    /// `EnvGuard`-style helper, `temp-env`, or `serial_test` anywhere in the
    /// tree. A shared helper for two unrelated variables in two unrelated test
    /// binaries would serialize tests that never contend; the first module
    /// that needs to share this variable with another is when to move it.
    fn statistics_env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// One blob with one declaration, so `ANALYZE` has rows to describe.
    fn insert_one_declaration(conn: &Connection) {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [OID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
               exact_fqn, synthetic, is_type_alias, in_declarations, in_definition_lookup
             )
             SELECT id, 'rust', 0, 0, 'Widget', 'Widget', '', 'pkg.Widget', 0, 0, 1, 1
             FROM blobs WHERE blob_oid = ?1",
            [OID],
        )
        .unwrap();
    }
}
