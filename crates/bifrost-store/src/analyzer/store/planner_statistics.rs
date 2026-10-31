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
    PlannerStatisticsRefresh, planner_statistics_row_count, refresh_planner_statistics,
    refresh_planner_statistics_if_stale,
};

use super::{AnalyzerStore, Result, StoreError};

impl AnalyzerStore {
    /// Collection refreshes statistics through its own connection. Reload
    /// that result without sampling the same database a second time.
    #[doc(hidden)]
    pub fn reload_planner_statistics(&self) -> Result<()> {
        self.conn.execute(|conn| -> Result<()> {
            conn.execute_batch("ANALYZE sqlite_schema;")?;
            conn.flush_prepared_statement_cache();
            Ok(())
        })?;
        self.recycle_readers_for_new_statistics();
        Ok(())
    }

    /// Recompute this store's query-planner statistics unconditionally.
    ///
    /// The build and garbage-collection hooks use
    /// [`Self::refresh_planner_statistics_if_stale`]; this one exists for
    /// callers that want the refresh to happen regardless, such as a benchmark
    /// measuring the same store with and without statistics.
    pub fn refresh_planner_statistics(&self) -> Result<PlannerStatisticsRefresh> {
        let evidence = self
            .conn
            .execute(|conn| refresh_planner_statistics(conn).map_err(StoreError::new))?;
        self.recycle_readers_for_new_statistics();
        Ok(evidence)
    }

    /// Refresh all tables outside the blob-count tolerance; otherwise refresh
    /// non-empty tables with missing statistics or ten-fold size changes.
    /// Build and GC hooks call this under their build or collection lock, since
    /// SQLite's dry-run optimize itself can take a write transaction.
    pub fn refresh_planner_statistics_if_stale(&self) -> Result<Option<PlannerStatisticsRefresh>> {
        let evidence = self
            .conn
            .execute(|conn| refresh_planner_statistics_if_stale(conn).map_err(StoreError::new))?;
        if evidence.is_some() {
            self.recycle_readers_for_new_statistics();
        }
        Ok(evidence)
    }

    /// Make this store's pooled readers plan against the statistics the
    /// database now holds, and report how many idle connections that closed.
    ///
    /// A reader loads `sqlite_stat1` when it first parses the schema and does
    /// not read it again: SQLite re-prepares a statement only when the schema
    /// cookie changes, and rewriting the rows of an existing `sqlite_stat1` is
    /// not a schema change. So a reader that has answered one query before a
    /// refresh keeps the plans it chose without it -- measured on
    /// `kivikakk/comrak`, where planning all forty pinned queries, refreshing,
    /// and planning them again on the same store reported zero plan changes,
    /// and ten as soon as the store was reopened between the two dumps (issue
    /// #3016's corpus report, finding F1). The first `ANALYZE` of a store's
    /// life hides this, because creating `sqlite_stat1` *is* a schema change;
    /// the collection hook, which rewrites an existing table, does not.
    ///
    /// Closing the connection is what fixes it, rather than the documented
    /// `ANALYZE sqlite_schema` reload: each reader also carries a prepared
    /// statement cache (`prepare_cached` backs the relational batch readers),
    /// and those compiled statements keep their plans across a statistics
    /// reload for the same reason. Dropping the connection drops both.
    ///
    /// A reader that is checked out right now finishes its query on the old
    /// plans and is closed when it comes back, which is the epoch stamp's job.
    pub fn recycle_readers_for_new_statistics(&self) -> usize {
        self.readers.recycle() + self.active_readers.recycle() + self.streaming_readers.recycle()
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
    ///
    /// `sqlite_stat4` goes with it. The bundled SQLite is built with
    /// `SQLITE_ENABLE_STAT4` (`libsqlite3-sys` 0.38 passes
    /// `-DSQLITE_ENABLE_STAT4`), so `ANALYZE` writes per-index samples there as
    /// well and the planner reads them; clearing only `sqlite_stat1` would
    /// leave a "before" measurement holding half of the statistics it means to
    /// remove.
    #[cfg(any(test, feature = "test-support"))]
    pub fn clear_planner_statistics(&self) -> Result<i64> {
        let rows = self.conn.execute(|conn| -> Result<i64> {
            let rows = planner_statistics_row_count(conn).map_err(StoreError::new)?;
            if rows == 0 {
                return Ok(0);
            }
            // A store analyzed by a build without `SQLITE_ENABLE_STAT4` -- the
            // system `sqlite3` CLI an operator might have run -- has no
            // `sqlite_stat4` table to clear.
            let sample_table: bool = conn
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM sqlite_schema
                       WHERE type = 'table' AND name = 'sqlite_stat4'
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    StoreError::new(format!("reading planner statistics tables: {error}"))
                })?;
            let clear_samples = if sample_table {
                "DELETE FROM sqlite_stat4;"
            } else {
                ""
            };
            conn.execute_batch(&format!(
                "DELETE FROM sqlite_stat1; {clear_samples} ANALYZE sqlite_schema;"
            ))
            .map_err(|error| StoreError::new(format!("clearing planner statistics: {error}")))?;
            Ok(rows)
        })?;
        if rows > 0 {
            self.recycle_readers_for_new_statistics();
        }
        Ok(rows)
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
    #[cfg(test)]
    fn python_reverse_candidate_pin() -> PinnedQuery {
        pin(
            "python_reverse_candidates",
            super::super::resolution_operation::reverse_candidates_sql(
                super::super::resolution_operation::python_reverse::PYTHON_REVERSE_ARMS,
            )
            .into_owned(),
            vec![],
        )
    }
    use rusqlite::types::Value;
    use rusqlite::{Connection, params_from_iter};

    use super::super::class_set_field_slots::{
        CLASS_SET_FIELD_SLOT_ARTIFACTS_SQL, CLASS_SET_FIELD_SLOT_ATOMS_SQL,
        CLASS_SET_FIELD_SLOT_INDEX_SQL, CLASS_SET_FIELD_SLOT_STORES_SQL, CLASS_SET_FIELD_SLOTS_SQL,
        PRUNE_OLD_CLASS_SET_FIELD_SLOT_INDEXES_SQL,
    };

    use super::super::class_set_procedure_surfaces::{
        CLASS_SET_PROCEDURE_SURFACE_DIGEST_SQL, CLASS_SET_PROCEDURE_SURFACE_FAMILY_SQL,
        SURFACE_BINDINGS_SQL, SURFACE_CALLS_SQL, SURFACE_ENTERED_SQL, SURFACE_LEXICAL_CHILDREN_SQL,
        SURFACE_READS_SQL,
    };

    use super::super::class_set_root_results::{
        CLASS_SET_ROOT_RESULT_HEADER_SQL, CLASS_SET_ROOT_RESULT_ROWS_SQL,
        PRUNE_OLD_CLASS_SET_ROOT_RESULT_GENERATIONS_SQL,
    };

    use super::super::class_set_summaries::{
        CHARGES_SQL, CLASS_SET_SUMMARY_DEPENDENTS_BY_LINEAGE_ENTRY_SQL,
        CLASS_SET_SUMMARY_DEPENDENTS_BY_LOOKUP_SQL, CLASS_SET_SUMMARY_DEPENDENTS_BY_READ_SQL,
        CLASS_SET_SUMMARY_FAMILY_SQL, CLASS_SET_SUMMARY_LOOKUP_SQL,
        CLASS_SET_SUMMARY_PROCEDURE_SQL, DEPENDENCIES_SQL, DEPENDENCY_SOURCES_SQL, EXITS_SQL,
        FACTS_SQL, REACHED_SQL, READS_SQL,
    };

    use super::super::resolution_operation::RUST_RECEIVER_KIND_SQL;
    use super::super::resolution_operation::jvm_context::SELECTED_JVM_ALIAS_DECLARATION_GAPS;
    use super::super::resolution_operation::selected_rust_declaration_authority_sql;
    use super::super::resolution_typed::RUST_RECEIVER_IMPL_TARGETS_SQL;
    use super::super::{
        AnalyzerStore, EXACT_PATH_SYMBOL_FQN_SQL, NORMALIZED_PATH_SYMBOL_FQN_SQL,
        REVERSE_IDENTIFIER_CANDIDATE_PATHS_SQL, REVERSE_IMPORT_CANDIDATE_BLOBS_SQL,
        REVERSE_TYPE_CANDIDATE_BLOBS_SQL, RUST_MODULE_IMPORT_CANDIDATE_BLOBS_SQL,
        RenderedTailMatch, Result, StoreError, WorkspaceSnapshots,
        batch_anchor_only_definition_candidate_sql, batch_component_definition_candidate_sql,
        candidate_fq_segments_sql, chunk_params, chunk_placeholders,
        cpp_search_owner_name_rows_sql, direct_children_limited_candidate_sql,
        enclosing_declarations_for_file_sql, identifier_prefix_candidate_sql,
        limited_identifier_candidate_for_blob_sql, limited_identifier_candidate_sql,
        mounted_declaration_sql, mounted_declaration_sql_with_primary_ranges, parsed_blob_keys_sql,
        persisted_blob_mutation_cost_fallback_sql, point_anchor_only_definition_candidate_sql,
        point_component_definition_candidate_sql, ranges_bulk_sql, raw_unit_fq_segments_sql,
        read_path_parsed_blob_condition, search_candidate_key_set_sql,
        search_candidate_name_rows_sql, signature_metadata_for_unit_sql,
        signature_metadata_projection_columns_sql, stored_blob_cascade_costs_sql,
        structural_fact_manifest_sql, sync_active_blob_oids, sync_reverse_reference_lookup_keys,
        workspace_content_package_facts_sql,
    };

    pub(crate) const OID: &str = "0123456789012345678901234567890123456789";
    pub(crate) const MEMBERSHIP: &str = "units.in_declarations = 1";

    /// The textual Rust macro-walk pins. These read the selected source path
    /// and summary membership, so
    /// `every_pinned_query_plans_in_both_statistics_states` asserts those
    /// seeks on exactly these names. The blob-keyed `rust_macro_*` source-row
    /// pins read only their source rows and are covered by
    /// `selected_macro_input_reads_seek_blob_and_invocation_in_both_statistics_states`.
    #[cfg(test)]
    pub(crate) const RUST_MACRO_WALK_QUERIES: [&str; 5] = [
        "rust_macro_walk_ancestry",
        "rust_macro_walk_child_module_files",
        "rust_macro_included_file",
        "rust_macro_include_starts",
        "rust_macro_host_files",
    ];

    /// Request counts the batch definition-candidate statements are pinned at
    /// (issue #3030).
    ///
    /// These statements carry their requests as a JSON array bound to `?1`, so
    /// nothing chunks them: `rendered_definition_order_candidate_rows_for_langs`
    /// serializes every component of every request in the caller's batch into
    /// one payload, and `TreeSitterAnalyzer::prefetch_definitions` builds that
    /// batch from however many names the resolver asked about. The rungs are
    /// therefore observations, not a chunk size. 6 is the smallest batch the
    /// `laravel/framework` profile issued (arity one goes down the point path
    /// instead) and 542 is the largest single statement in it, the one that
    /// took 58.7 s without planner statistics; the rest space the range.
    ///
    /// A ladder is worth pinning even though the SQL text is the same at every
    /// rung, because the bundled SQLite is built with `SQLITE_ENABLE_STAT4`
    /// (`libsqlite3-sys` 0.38 passes `-DSQLITE_ENABLE_STAT4`) and a STAT4 build
    /// re-prepares a statement using its bound parameter values. The bound
    /// payload is an input to planning, so "the pin plans the same statement"
    /// is not by itself "the pin plans production's statement".
    pub const DEFINITION_CANDIDATE_ARITY_LADDER: [usize; 5] = [6, 16, 64, 256, 542];

    /// One `[request_index, prefix, tail, normalized, anchored]` row per
    /// request, shaped exactly as
    /// `rendered_definition_order_candidate_rows_for_langs` serializes them.
    ///
    /// Prefixes and tails vary per row because STAT4 plans from the bound
    /// values: a payload repeating one package name would describe a batch
    /// production does not issue.
    fn definition_request_payload(arity: usize, anchor_only: bool) -> String {
        let rows = (0..arity)
            .map(|index| {
                (
                    index,
                    format!("pkg.module{index}"),
                    if anchor_only {
                        String::new()
                    } else {
                        format!("Widget{index}")
                    },
                    0,
                    1,
                )
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&rows).expect("definition request payload serializes")
    }

    fn text(value: &str) -> Value {
        Value::Text(value.to_string())
    }

    fn integer(value: i64) -> Value {
        Value::Integer(value)
    }

    fn digest(value: u8) -> Value {
        Value::Blob(vec![value; 32])
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

    /// Demand-terminal reader statements, also included in the complete registry.
    ///
    /// The header readers bind a first or last symbol as its persisted
    /// identity id, the integer `identity_id` holds, so the pins bind one too:
    /// a STAT4 build plans from the bound value.
    pub fn root_terminal_demand_queries() -> Vec<PinnedQuery> {
        vec![
            pin(
                "selected_path_endpoint_header_mounts",
                super::super::resolution_lexical::PATH_ENDPOINT_HEADER_MOUNTS_SQL,
                vec![text("forward"), integer(7), integer(1), integer(1)],
            ),
            pin(
                "selected_scoped_path_endpoint_header_mounts",
                super::super::resolution_lexical::SCOPED_PATH_ENDPOINT_HEADER_MOUNTS_SQL,
                vec![
                    text("forward"),
                    integer(7),
                    integer(0),
                    integer(1),
                    text("[0]"),
                ],
            ),
            pin(
                "selected_path_terminal_header_mounts",
                super::super::resolution_lexical::PATH_TERMINAL_HEADER_MOUNTS_SQL,
                vec![integer(7)],
            ),
            pin(
                "selected_unconditional_candidate_gap_reasons",
                super::super::resolution_lexical::CANDIDATE_GAP_UNCONDITIONAL_SQL,
                vec![integer(2)],
            ),
            pin(
                "selected_unconditional_candidate_gap_reasons_in_mounts",
                super::super::resolution_lexical::CANDIDATE_GAP_UNCONDITIONAL_IN_MOUNTS_SQL,
                vec![integer(2), text("[0,7]")],
            ),
            pin(
                "selected_boundary_candidate_gap_branches",
                super::super::resolution_lexical::CANDIDATE_GAP_BOUNDARY_BRANCHES_SQL,
                vec![integer(5), text("[0,7]")],
            ),
            pin(
                "selected_boundary_candidate_gap_branches_all",
                super::super::resolution_lexical::CANDIDATE_GAP_BOUNDARY_BRANCHES_ALL_SQL,
                vec![integer(5)],
            ),
            pin(
                "selected_boundary_candidate_gap_branches_in_mounts",
                super::super::resolution_lexical::CANDIDATE_GAP_BOUNDARY_BRANCHES_IN_MOUNTS_SQL,
                vec![integer(5), text("[0,7]"), text("[1,3]")],
            ),
            pin(
                "selected_boundary_candidate_gap_branches_all_in_mounts",
                super::super::resolution_lexical::CANDIDATE_GAP_BOUNDARY_BRANCHES_ALL_IN_MOUNTS_SQL,
                vec![integer(5), text("[1,3]")],
            ),
            pin(
                "selected_endpoint_candidate_gap_branches",
                super::super::resolution_lexical::CANDIDATE_GAP_ENDPOINT_BRANCHES_SQL,
                vec![integer(1), integer(5), text("[[1,0],[1,2]]"), text("[2]")],
            ),
        ]
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
        crate::analyzer::store::rust_crates::prepare_pin_context(conn).expect("crate SQL context");
        conn.execute_batch(
            super::super::rust_unit_summaries::RUST_IMPORT_GRAPH_MEMBER_SELECTION_SQL,
        )
        .expect("Rust import graph member selection view");
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
        conn.execute_batch(super::super::python_unit_summaries::STAGING)
            .expect("Python environment staging tables");
        super::super::ensure_revisioned_workspace_views(conn)
            .expect("revisioned workspace query views");
        conn.execute_batch(super::super::resolution_operation::REVERSE_CANDIDATE_KEYS_DDL)
            .expect("reverse candidate request keys");
        super::super::ensure_declaration_candidate_requests_table(conn)
            .expect("identifier candidate request table");
        crate::analyzer::store::resolution_lexical::register_resolution_identity_functions(conn)
            .expect("resolution identity SQL functions");
        crate::analyzer::store::go_unit_summaries::register_go_summary_sql_functions(conn)
            .expect("Go summary SQL functions");
        crate::analyzer::store::rust_crates::prepare_pin_context(conn).expect("crate SQL context");
        // The authority reader is normally planned against the selected
        // operation's connection, where this temp table is already installed.
        // Keep the registry self-contained for ephemeral planner-pin stores,
        // preserving the production mount table's WITHOUT ROWID key layout.
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS unit_summary_order(ordinal INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL UNIQUE, unit_key BLOB UNIQUE) STRICT;
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_overlay_masks(storage_language TEXT NOT NULL, persisted_relative_path TEXT NOT NULL, intent TEXT NOT NULL DEFAULT 'replacement', masked_file_version_id INTEGER, masked_blob_oid TEXT, masked_projection_digest BLOB, expected_transient_replacement_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(storage_language,persisted_relative_path)) WITHOUT ROWID;
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_mounts(
                mount_ordinal INTEGER PRIMARY KEY,
                file_version_id INTEGER UNIQUE,
                blob_id INTEGER,
                workspace_id TEXT,
                generation INTEGER,
                revision INTEGER,
                blob_oid TEXT,
                storage_language TEXT,
                semantic_language TEXT,
                producer_epoch TEXT,
                interior_digest BLOB,
                persisted_relative_path TEXT,
                UNIQUE(storage_language, persisted_relative_path)
             ) WITHOUT ROWID, STRICT;
             CREATE INDEX IF NOT EXISTS temp.selected_resolution_mounts_blob_ordinal
               ON selected_resolution_mounts(blob_id, mount_ordinal);
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_scope_mounts(
               mount_ordinal INTEGER NOT NULL PRIMARY KEY CHECK(mount_ordinal >= 0)
             ) WITHOUT ROWID, STRICT;",
        )
        .expect("selected resolution mount pin table");
        conn.execute_batch(
            crate::analyzer::store::resolution_operation::go_context::GO_TRANSIENT_PLACEMENTS_SQL,
        )
        .expect("selected Go transient placement pin view");
        super::super::go_unit_summaries::install_go_summary_sources(conn)
            .expect("Go summary revision pin view");
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_SCHEMA_SQL)
            .expect("selected Rust module placement pin table");
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL)
            .expect("selected Rust module placement pin rows");
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_reverse_rows::GAP_CANDIDATE_SITES_SCHEMA_SQL)
            .expect("selected Rust reverse gap site pin table");
        conn.execute_batch(crate::analyzer::store::resolution_stage::schema_sql())
            .expect("selected resolution stage pin tables");
        sync_active_blob_oids(conn, &[]).expect("active blob temp table");
        sync_reverse_reference_lookup_keys(
            conn,
            &["Target".to_string()].into_iter().collect(),
            &["pkg".to_string()].into_iter().collect(),
            &["Target".to_string()].into_iter().collect(),
        )
        .expect("reverse lookup temp tables");
        conn.execute_batch(
            super::super::rust_unit_summaries::RUST_IMPORT_GRAPH_MEMBER_SELECTION_SQL,
        )
        .expect("Rust import graph member selection view");
    }

    /// The typed-fact statements that take one blob and one key array, with the
    /// name each is pinned and planned under (milestone 6 port block 4, lane TF).
    ///
    /// The table is the one place the list lives: `pinned_queries` registers it
    /// and the plan pin below walks the same list, so a statement cannot be added
    /// to the reader and left unplanned.
    pub(super) const TYPED_FACT_PINS: &[(&str, &str)] = &[
        (
            "resolution_rust_reason_owners",
            crate::analyzer::store::resolution_operation::rust_crate_access::REASON_OWNERS_SQL,
        ),
        (
            "resolution_type_frontiers_by_slot",
            crate::analyzer::store::resolution_prepare::typed_rows::TYPE_FRONTIERS_BY_SLOT_SQL,
        ),
        (
            "resolution_type_frontiers_by_reference",
            crate::analyzer::store::resolution_prepare::typed_rows::TYPE_FRONTIERS_BY_REFERENCE_SQL,
        ),
        (
            "resolution_type_transfers_by_source",
            crate::analyzer::store::resolution_prepare::typed_rows::TYPE_TRANSFERS_BY_SOURCE_SQL,
        ),
        (
            "resolution_type_transfers_by_target",
            crate::analyzer::store::resolution_prepare::typed_rows::TYPE_TRANSFERS_BY_TARGET_SQL,
        ),
        (
            "resolution_intrinsic_seeds_by_slot",
            crate::analyzer::store::resolution_prepare::typed_rows::INTRINSIC_SEEDS_BY_SLOT_SQL,
        ),
        (
            "resolution_intrinsic_seeds_by_identity",
            crate::analyzer::store::resolution_prepare::typed_rows::INTRINSIC_SEEDS_BY_IDENTITY_SQL,
        ),
        (
            "resolution_binding_projections_by_reference",
            crate::analyzer::store::resolution_prepare::typed_rows::BINDING_PROJECTIONS_BY_REFERENCE_SQL,
        ),
        (
            "resolution_binding_projections_by_output",
            crate::analyzer::store::resolution_prepare::typed_rows::BINDING_PROJECTIONS_BY_OUTPUT_SQL,
        ),
        (
            "resolution_qualified_routes_by_reference",
            crate::analyzer::store::resolution_prepare::typed_rows::QUALIFIED_ROUTES_BY_REFERENCE_SQL,
        ),
        (
            "resolution_qualified_routes_by_qualifier_slot",
            crate::analyzer::store::resolution_prepare::typed_rows::QUALIFIED_ROUTES_BY_QUALIFIER_SLOT_SQL,
        ),
        (
            "resolution_qualified_routes_by_lookup",
            crate::analyzer::store::resolution_prepare::typed_rows::QUALIFIED_ROUTES_BY_LOOKUP_SQL,
        ),
        (
            "resolution_qualified_routes_by_gap_reason",
            crate::analyzer::store::resolution_prepare::typed_rows::QUALIFIED_ROUTES_BY_GAP_REASON_SQL,
        ),
        (
            "resolution_declaration_types_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::DECLARATION_TYPES_BY_DEFINITION_SQL,
        ),
        (
            "resolution_declaration_types_by_slot",
            crate::analyzer::store::resolution_prepare::typed_rows::DECLARATION_TYPES_BY_SLOT_SQL,
        ),
        (
            "resolution_declaration_visibilities_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::DECLARATION_VISIBILITIES_BY_DEFINITION_SQL,
        ),
        (
            "resolution_member_scopes_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::MEMBER_SCOPES_BY_DEFINITION_SQL,
        ),
        (
            "resolution_member_scopes_by_head",
            crate::analyzer::store::resolution_prepare::typed_rows::MEMBER_SCOPES_BY_HEAD_SQL,
        ),
        (
            "resolution_jvm_aliases_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::JVM_ALIASES_BY_DEFINITION_SQL,
        ),
        (
            "resolution_member_owners_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::MEMBER_OWNERS_BY_DEFINITION_SQL,
        ),
        (
            "resolution_member_owners_by_owner",
            crate::analyzer::store::resolution_prepare::typed_rows::MEMBER_OWNERS_BY_OWNER_SQL,
        ),
        (
            "resolution_deferred_member_owners_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::DEFERRED_MEMBER_OWNERS_BY_DEFINITION_SQL,
        ),
        (
            "resolution_deferred_member_owners_by_lookup",
            crate::analyzer::store::resolution_prepare::typed_rows::DEFERRED_MEMBER_OWNERS_BY_LOOKUP_SQL,
        ),
        (
            "resolution_construction_requirements_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::CONSTRUCTION_REQUIREMENTS_BY_DEFINITION_SQL,
        ),
        (
            "resolution_supertypes_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::SUPERTYPES_BY_DEFINITION_SQL,
        ),
        (
            "resolution_supertypes_by_reference",
            crate::analyzer::store::resolution_prepare::typed_rows::SUPERTYPES_BY_REFERENCE_SQL,
        ),
        (
            "resolution_supertypes_by_frontier",
            crate::analyzer::store::resolution_prepare::typed_rows::SUPERTYPES_BY_FRONTIER_SQL,
        ),
        (
            "resolution_definition_property_gaps_by_reason",
            crate::analyzer::store::resolution_prepare::typed_rows::DEFINITION_PROPERTY_GAPS_BY_REASON_SQL,
        ),
        (
            "resolution_definition_property_gaps_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::DEFINITION_PROPERTY_GAPS_BY_DEFINITION_SQL,
        ),
        (
            "resolution_call_obligations_by_callee",
            crate::analyzer::store::resolution_prepare::typed_rows::CALL_OBLIGATIONS_BY_CALLEE_SQL,
        ),
        (
            "resolution_call_obligations_by_reason",
            crate::analyzer::store::resolution_prepare::typed_rows::CALL_OBLIGATIONS_BY_REASON_SQL,
        ),
        (
            "resolution_callable_signatures_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::CALLABLE_SIGNATURES_BY_DEFINITION_SQL,
        ),
    ];

    /// Scalar ownership and payload seeks bind the blob followed by exact
    /// integer keys. Provenance uses reason, source site and property kind;
    /// the other seeks use one rule, call, node or parameter definition key.
    pub(super) const TYPED_OWNER_PINS: &[(&str, &str, &[i64])] = &[
        (
            "resolution_type_transfer_owner_by_rule",
            crate::analyzer::store::resolution_prepare::typed_rows::TYPE_TRANSFER_OWNER_BY_RULE_SQL,
            &[1, 0],
        ),
        (
            "resolution_call_obligation_owner_by_call",
            crate::analyzer::store::resolution_prepare::typed_rows::CALL_OBLIGATION_OWNER_BY_CALL_SQL,
            &[1, 0],
        ),
        (
            "resolution_property_gap_owner_by_provenance",
            crate::analyzer::store::resolution_prepare::typed_rows::PROPERTY_GAP_OWNER_BY_PROVENANCE_SQL,
            &[1, 777777, 77, 3], // blob, reason, source site, property kind
        ),
        (
            "resolution_node_catalog_payload_by_key",
            crate::analyzer::store::resolution::NODE_CATALOG_PAYLOAD_BY_KEY_SQL,
            &[1, 0],
        ),
        (
            "resolution_callable_parameter_owner_by_definition",
            crate::analyzer::store::resolution_prepare::typed_rows::CALLABLE_PARAMETER_OWNER_BY_DEFINITION_SQL,
            &[1, 0],
        ),
    ];

    #[cfg(test)]
    fn rust_macro_source_row_pins() -> [PinnedQuery; 3] {
        use crate::analyzer::store::rust_macro_source_sql::{
            RUST_MACRO_INPUT_EXISTS_SQL, RUST_MACRO_INVOCATION_INPUT_SQL,
            RUST_MACRO_INVOCATION_TOKENS_SQL,
        };

        [
            pin(
                "rust_macro_input_exists",
                RUST_MACRO_INPUT_EXISTS_SQL,
                vec![integer(1)],
            ),
            pin(
                "rust_macro_invocation_input",
                RUST_MACRO_INVOCATION_INPUT_SQL,
                vec![integer(1), integer(16)],
            ),
            pin(
                "rust_macro_invocation_tokens",
                RUST_MACRO_INVOCATION_TOKENS_SQL,
                vec![integer(1), integer(2)],
            ),
        ]
    }

    /// Every EXPLAIN QUERY PLAN pin this crate's store module owns, as data.
    ///
    /// This is where each of those statements is written, once. The pin tests
    /// in `store/mod.rs` fetch their subject from here with [`pinned`], and the
    /// two operator dumps below replay the whole list against a real
    /// repository store and against the captured statistics. Before this
    /// registry existed the dump carried its own copy of every statement and
    /// could drift from the test that asserts on it.
    /// Catalog pins run on the active-set TEMP views, not an analyzer store.
    /// The language-wide absence inventory is a broad stream, not a selective
    /// question; its plan can legitimately scan the complete selected realm.
    pub fn semantic_catalog_pins() -> Vec<(PinnedQuery, &'static str)> {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements as q;
        vec![
            (
                pin(
                    "semantic_search_owner_qualifications",
                    q::SEARCH_OWNER_QUALIFICATIONS,
                    vec![text(r#"["Owner17"]"#)],
                ),
                "catalog_declaration_types_id",
            ),
            (
                pin(
                    "semantic_search_types_by_ids",
                    q::TYPES_BY_IDS,
                    vec![text(r#"["Owner17"]"#)],
                ),
                "catalog_declaration_types_id",
            ),
            (
                pin(
                    "semantic_search_members_by_ids",
                    q::MEMBERS_BY_IDS,
                    vec![text(r#"["Member17"]"#)],
                ),
                "catalog_declaration_members_id",
            ),
            (
                pin(
                    "semantic_search_candidates",
                    q::SEARCH_ORDERED_CANDIDATES,
                    vec![
                        text(r#"[{"language":"rust","id":"Owner17","name":"qualified.Owner17"}]"#),
                        text(
                            r#"[{"source_db":"durable","shard_key":1,"digest":"pack"},{"source_db":"session","shard_key":1,"digest":"pack"}]"#,
                        ),
                    ],
                ),
                "AUTOMATIC COVERING INDEX",
            ),
            (
                pin(
                    "semantic_payload_family_presence",
                    q::PAYLOAD_FAMILY_PRESENCE,
                    vec![text("durable"), integer(1), text("callable_values")],
                ),
                "sqlite_autoindex_catalog_semantic_payload_families_1",
            ),
            (
                pin(
                    "semantic_summary_absent_owners",
                    q::SUMMARY_ABSENT_OWNERS,
                    vec![text("rust"), text("name17"), integer(0)],
                ),
                "catalog_procedure_summaries_absence",
            ),
            (
                pin(
                    "semantic_summary_member_candidates",
                    q::SUMMARY_MEMBER_CANDIDATES,
                    vec![text("rust"), text("name17"), integer(0)],
                ),
                "catalog_procedure_summaries_absence",
            ),
            (
                pin(
                    "semantic_summary_receiverless",
                    q::SUMMARY_RECEIVERLESS,
                    vec![text("rust"), text("Owner17"), text("name17")],
                ),
                "catalog_procedure_summaries_member",
            ),
            (
                pin(
                    "semantic_summary_shard_first",
                    q::SUMMARY_SHARD_FIRST,
                    vec![text("durable"), integer(1)],
                ),
                "catalog_procedure_summaries_record_id",
            ),
            (
                pin(
                    "semantic_summary_shard_sequence",
                    q::SUMMARY_SHARD_SEQUENCE,
                    vec![text("durable"), integer(1)],
                ),
                "catalog_procedure_summaries_record_id",
            ),
            (
                pin(
                    "semantic_group_owner_ids",
                    q::GROUP_OWNER_IDS,
                    vec![text("Type17"), text("rust"), text("type")],
                ),
                "catalog_declaration_names_lookup",
            ),
            (
                pin(
                    "semantic_group_member_ids",
                    q::MEMBER_IDS_BY_OWNERS,
                    vec![text("[\"Owner17\"]")],
                ),
                "catalog_declaration_members_owner_name",
            ),
            (
                pin("semantic_names", q::TYPES_BY_NAME, vec![text("Type17")]),
                "catalog_declaration_names_lookup",
            ),
            (
                pin(
                    "semantic_member_owner_name",
                    q::MEMBERS_BY_OWNER_NAME,
                    vec![text("Owner17"), text("name17")],
                ),
                "catalog_declaration_members_owner_name",
            ),
            (
                pin(
                    "semantic_member_name_language",
                    q::MEMBERS_BY_NAME_LANGUAGE,
                    vec![text("name17"), text("rust")],
                ),
                "catalog_declaration_members_name",
            ),
            (
                pin(
                    "semantic_relations_from",
                    q::RELATIONS_FROM,
                    vec![text("Type17")],
                ),
                "catalog_declaration_relations_from",
            ),
            (
                pin(
                    "semantic_relations_to",
                    q::RELATIONS_TO,
                    vec![text("Base17")],
                ),
                "catalog_declaration_relations_to",
            ),
            (
                pin(
                    "semantic_summary_target",
                    q::SUMMARY_TARGET,
                    vec![
                        text("rust"),
                        text("path17"),
                        text("symbol17"),
                        integer(0),
                        integer(0),
                    ],
                ),
                "catalog_procedure_summaries_target",
            ),
            (
                pin(
                    "semantic_summary_path",
                    q::SUMMARY_PATH,
                    vec![text("rust"), text("path17")],
                ),
                "catalog_procedure_summaries_target",
            ),
            (
                pin(
                    "semantic_summary_target_family",
                    q::SUMMARY_TARGET_FAMILY,
                    vec![text("rust"), text("path17"), text("symbol17"), integer(0)],
                ),
                "catalog_procedure_summaries_target",
            ),
            (
                pin(
                    "semantic_summary_member",
                    q::SUMMARY_MEMBER,
                    vec![
                        text("rust"),
                        text("[\"Owner17\"]"),
                        text("name17"),
                        integer(0),
                    ],
                ),
                "catalog_procedure_summaries_member",
            ),
            (
                pin(
                    "semantic_summary_applicable",
                    q::SUMMARY_APPLICABLE,
                    vec![
                        text("rust"),
                        text("[\"Owner17\"]"),
                        text("name17"),
                        integer(0),
                        integer(0),
                    ],
                ),
                "catalog_procedure_summaries_member",
            ),
            (
                pin(
                    "semantic_summary_id",
                    q::SUMMARY_BY_ID,
                    vec![text("durable"), integer(1), text("sum17")],
                ),
                "catalog_procedure_summaries_record_id",
            ),
        ]
    }

    pub fn pinned_queries() -> Vec<PinnedQuery> {
        let mut queries = vec![pin(
            "jvm_native_source_membership",
            super::super::jvm_package_context::JVM_NATIVE_SOURCE_MEMBERSHIP_SQL,
            vec![
                integer(1),
                integer(1),
                text("module3/src/main/"),
                text("module3/src/main0"),
            ],
        )];
        queries.push(pin(
            "rust_receiver_impl_targets",
            RUST_RECEIVER_IMPL_TARGETS_SQL,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "rust_receiver_kind",
            RUST_RECEIVER_KIND_SQL,
            vec![integer(1), integer(1)],
        ));
        // Real codec parameters exercise closed, open and proper-prefix arms.
        let root_requests = {
            use crate::analyzer::resolution::{
                BatchCandidateRequest, BindingNodeId, EndpointSignature, SemanticId, StackPattern,
                StackVariableId,
            };
            let requests = [
                (vec![], false),
                (vec![SemanticId::local(0, 1)], false),
                (vec![SemanticId::local(0, 1), SemanticId::local(0, 2)], true),
            ]
            .into_iter()
            .enumerate()
            .map(|(ordinal, (cells, open))| {
                let request = BatchCandidateRequest::new(
                    ordinal,
                    EndpointSignature::new(
                        BindingNodeId::universal_root(),
                        StackPattern::new(cells, open.then(|| StackVariableId::operation_local(0))),
                        StackPattern::closed(vec![]),
                    ),
                );
                serde_json::from_str::<serde_json::Value>(
                    &super::super::resolution_stage::codec::root_candidate_request(
                        ordinal,
                        &request,
                        &crate::CancellationToken::new(),
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
            serde_json::to_string(&requests).unwrap()
        };
        queries.extend([
            pin(
                "context_forward_root_seek",
                super::super::resolution_stage::lexical_readers::CONTEXT_FORWARD_CANDIDATES_SQL
                    .as_str(),
                vec![integer(1), text("[[3,7]]"), text(&root_requests)],
            ),
            pin(
                "context_reverse_root_seek",
                super::super::resolution_stage::lexical_readers::CONTEXT_REVERSE_CANDIDATES_SQL
                    .as_str(),
                vec![integer(1), text("[[3,7]]"), text(&root_requests)],
            ),
            pin(
                "stage_reverse_root_seek",
                super::super::resolution_stage::lexical_readers::reverse_candidate_sql(),
                vec![
                    Value::Null,
                    text("[[4,7,null,1,false]]"),
                    text("[[5,7]]"),
                    text("[[6,7]]"),
                    text(&root_requests),
                    text("[[7,1,0]]"),
                ],
            ),
        ]);
        queries.push(pin(
            "go_interval_resolution_operation_go_named_selected_external_imports",
            super::super::resolution_operation::go_named::SELECTED_EXTERNAL_IMPORTS.as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_named_selected_unresolved_imports",
            super::super::resolution_operation::go_named::SELECTED_UNRESOLVED_IMPORTS.as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_named_selected_import_context_files",
            super::super::resolution_operation::go_named::SELECTED_IMPORT_CONTEXT_FILES.as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_named_caller_source_role",
            super::super::resolution_operation::go_named::CALLER_SOURCE_ROLE.as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_named_go_file_import_rows",
            super::super::resolution_operation::go_named::GO_FILE_IMPORT_ROWS.as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_named_go_interval_go_graph_file_exclusion_0_sql",
            super::super::resolution_operation::go_named::GO_INTERVAL_GO_GRAPH_FILE_EXCLUSION_0_SQL
                .as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_named_go_interval_go_graph_file_exclusion_1_sql",
            super::super::resolution_operation::go_named::GO_INTERVAL_GO_GRAPH_FILE_EXCLUSION_1_SQL
                .as_str(),
            vec![integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_named_named_import_target_mounts",
            super::super::resolution_operation::go_named::NAMED_IMPORT_TARGET_MOUNTS,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_demand_go_interval_discovery_scope_0_sql",
            super::super::resolution_operation::go_demand::GO_INTERVAL_DISCOVERY_SCOPE_0_SQL
                .as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_reverse_rows_go_reverse_candidate_sites_sql",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_CANDIDATE_SITES_SQL
                .as_str(),
            vec![
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin("go_interval_resolution_operation_go_reverse_rows_go_reverse_transient_alias_exports_sql", super::super::resolution_operation::go_reverse_rows::GO_REVERSE_TRANSIENT_ALIAS_EXPORTS_SQL, vec![integer(1),integer(1),integer(1),integer(1),integer(1),integer(1),integer(1),integer(1),integer(1),integer(1),integer(1),integer(1)]));
        queries.push(pin(
            "go_interval_resolution_operation_go_reverse_rows_go_reverse_qualified_import_sql",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_QUALIFIED_IMPORT_SQL,
            vec![
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_reverse_rows_go_reverse_dot_export_rows_sql",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_DOT_EXPORT_ROWS_SQL,
            vec![
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_reverse_rows_go_reverse_inventory_complete_sql",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_INVENTORY_COMPLETE_SQL
                .as_str(),
            vec![
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_reverse_rows_go_rename_target_units_sql",
            super::super::resolution_operation::go_reverse_rows::GO_RENAME_TARGET_UNITS_SQL
                .as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin("go_interval_resolution_operation_go_reverse_rows_go_interval_go_reverse_candidate_sites_0_sql", super::super::resolution_operation::go_reverse_rows::GO_INTERVAL_GO_REVERSE_CANDIDATE_SITES_0_SQL, vec![integer(1),integer(1)]));
        queries.push(pin(
            "go_interval_resolution_operation_go_same_package_caller_package",
            super::super::resolution_operation::go_same_package::CALLER_PACKAGE.as_str(),
            vec![integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_same_package_package_peer_mounts",
            super::super::resolution_operation::go_same_package::PACKAGE_PEER_MOUNTS,
            vec![integer(1), integer(1), integer(1)],
        ));
        queries.push(pin("go_interval_resolution_operation_go_same_package_point_package_with_unselected_source", super::super::resolution_operation::go_same_package::POINT_PACKAGE_WITH_UNSELECTED_SOURCE.as_str(), vec![integer(1),integer(1),integer(1),integer(1)]));
        queries.push(pin(
            "go_interval_resolution_operation_go_context_package_source_mounts",
            super::super::resolution_operation::go_context::PACKAGE_SOURCE_MOUNTS,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_context_dot_import_target_mounts",
            super::super::resolution_operation::go_context::DOT_IMPORT_TARGET_MOUNTS.as_str(),
            vec![integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_receiver_anchor_go_point_null_receiver_frontier",
            super::super::resolution_operation::go_receiver_anchor::GO_POINT_NULL_RECEIVER_FRONTIER
                .as_str(),
            vec![integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_receiver_anchor_go_point_receiver_anchor",
            super::super::resolution_operation::go_receiver_anchor::GO_POINT_RECEIVER_ANCHOR,
            vec![
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_interval_resolution_operation_go_receiver_anchor_go_point_callable_result_anchor",
            super::super::resolution_operation::go_receiver_anchor::GO_POINT_CALLABLE_RESULT_ANCHOR,
            vec![integer(1), integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin("go_interval_resolution_operation_go_receiver_anchor_go_receiver_anchor_declared_type", super::super::resolution_operation::go_receiver_anchor::GO_RECEIVER_ANCHOR_DECLARED_TYPE, vec![integer(1),integer(1),integer(1),integer(1),integer(1),integer(1)]));
        queries.push(pin(
            "go_interval_resolution_operation_go_receiver_anchor_go_receiver_anchor_member",
            super::super::resolution_operation::go_receiver_anchor::GO_RECEIVER_ANCHOR_MEMBER,
            vec![
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin("go_interval_resolution_operation_go_method_family_go_interval_go_method_identity_0_sql", super::super::resolution_operation::go_method_family::GO_INTERVAL_GO_METHOD_IDENTITY_0_SQL.as_str(), vec![integer(1),integer(1),integer(1)]));
        queries.push(pin("go_interval_resolution_operation_go_method_family_go_interval_go_method_family_1_sql", super::super::resolution_operation::go_method_family::GO_INTERVAL_GO_METHOD_FAMILY_1_SQL.as_str(), vec![integer(1),integer(1)]));
        queries.push(pin(
            "go_interval_resolution_typed_go_members_owner_proofs",
            super::super::resolution_typed::go_members::OWNER_PROOFS,
            vec![integer(1)],
        ));
        queries.push(pin(
            "go_interval_go_unit_summaries_stage_units_sql",
            super::super::go_unit_summaries::STAGE_UNITS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "go_interval_go_unit_summaries_unit_members_sql",
            super::super::go_unit_summaries::UNIT_MEMBERS_SQL,
            vec![integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_go_unit_summaries_members_without_bundle_sql",
            super::super::go_unit_summaries::MEMBERS_WITHOUT_BUNDLE_SQL,
            vec![integer(1), integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_go_unit_summaries_unit_exports_sql",
            super::super::go_unit_summaries::UNIT_EXPORTS_SQL,
            vec![integer(1), integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_go_unit_summaries_unit_alias_exports_sql",
            super::super::go_unit_summaries::UNIT_ALIAS_EXPORTS_SQL,
            vec![integer(1), integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_interval_go_unit_summaries_unit_imports_sql",
            super::super::go_unit_summaries::UNIT_IMPORTS_SQL,
            vec![integer(1), integer(1), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_domain_for_module",
            super::super::resolution_operation::go_named::DOMAIN_FOR_MODULE_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
                digest(1),
                integer(1),
                text("nested"),
            ],
        ));
        queries.push(pin(
            "go_import_discovery_failures_ordered_spelling",
            super::super::resolution_operation::go_context::GO_IMPORT_DISCOVERY_FAILURES_SQL,
            vec![integer(1), text("[\"main.go\"]")],
        ));
        queries.push(pin(
            "go_domain_discovery_failure",
            super::super::resolution_operation::go_context::DOMAIN_DISCOVERY_FAILURE_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "go_domain_contexts_for_definition_file",
            super::super::go_package_context::OWNER_CONTEXT_FOR_DEFINITION_FILE_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
                digest(1),
                integer(1),
                text("main.go"),
            ],
        ));
        queries.push(pin(
            "go_domain_caller_context_publishes_file",
            super::super::resolution_operation::go_context::CALLER_CONTEXT_PUBLISHES_FILE,
            vec![text("pkg/1/main.go"), integer(1)],
        ));
        queries.push(pin(
            "go_domain_package_member_sources",
            super::super::resolution_typed::go_members::PACKAGE_MEMBER_SOURCES,
            vec![integer(1), integer(0), integer(1), integer(1), text("go")],
        ));
        queries.push(pin(
            "go_domain_deferred_member_participation",
            super::super::resolution_typed::go_members::SOURCE_PARTICIPATION.as_str(),
            vec![text("[0]"), integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_domain_contexts_for_file",
            super::super::go_package_context::CONTEXTS_FOR_FILE_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
                digest(1),
                integer(1),
                text("main.go"),
            ],
        ));
        queries.push(pin(
            "go_dead_code_outside_build_files",
            super::super::go_package_context::OUTSIDE_SELECTED_BUILD_FILES_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
                digest(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "source_reference_names_in_files",
            super::super::source_facts::REFERENCE_NAMES_IN_FILES_SQL,
            vec![text(r#"[["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","go",1,1,"main.go"]]"#), text(r#"["helper"]"#)],
        ));
        queries.push(pin(
            "go_domain_missing_members",
            super::super::go_package_context::MISSING_MEMBER_PATHS_SQL,
            vec![integer(1), integer(1)],
        ));
        queries.extend([
            pin(
                "python_env_select_files",
                super::super::python_unit_summaries::SELECT_FILES,
                vec![text(&"e".repeat(64)), integer(0), integer(1)],
            ),
            pin(
                "python_env_stage_files",
                super::super::python_unit_summaries::STAGE_FILES,
                vec![text(&"e".repeat(64)), integer(0), integer(1)],
            ),
            pin(
                "python_env_stage_roots",
                format!(
                    "{} {}",
                    super::super::python_unit_summaries::stage_roots_prefix(),
                    super::super::python_unit_summaries::STAGE_ROOT_ROW
                ),
                vec![integer(0), text("")],
            ),
            pin(
                "python_env_stage_candidates",
                format!(
                    "{} {}",
                    super::super::python_unit_summaries::stage_candidates_prefix(),
                    super::super::python_unit_summaries::STAGE_CANDIDATE_ROW
                ),
                vec![
                    text("provider"),
                    text("file1"),
                    text(""),
                    integer(1),
                    integer(0),
                    text("module"),
                    text("file1.py"),
                    integer(1),
                    integer(0),
                    digest(0),
                ],
            ),
            pin(
                "python_env_stage_imports",
                super::super::python_unit_summaries::STAGE_IMPORTS,
                vec![],
            ),
            pin(
                "python_env_stage_segments",
                super::super::python_unit_summaries::STAGE_SEGMENTS,
                vec![],
            ),
            pin(
                "python_env_stage_surfaces",
                super::super::python_unit_summaries::STAGE_SURFACES,
                vec![],
            ),
            pin(
                "python_env_stage_module_names",
                super::super::python_unit_summaries::STAGE_MODULE_NAMES,
                vec![],
            ),
            pin(
                "python_env_stage_curated_names",
                super::super::python_unit_summaries::STAGE_CURATED_NAMES,
                vec![],
            ),
            pin(
                "python_env_stage_wildcard_names",
                super::super::python_unit_summaries::STAGE_WILDCARD_NAMES,
                vec![],
            ),
            pin(
                "python_env_select_route_inputs",
                super::super::python_unit_summaries::SELECT_ROUTE_INPUTS,
                vec![],
            ),
            pin(
                "python_env_stage_route_inputs",
                format!(
                    "{} {}",
                    super::super::python_unit_summaries::stage_route_inputs_prefix(),
                    super::super::python_unit_summaries::STAGE_ROUTE_INPUT_ROW
                ),
                vec![
                    text("file1.py"),
                    integer(0),
                    text("provider"),
                    text("module"),
                    integer(1),
                ],
            ),
            pin(
                "python_env_stage_routes",
                super::super::python_unit_summaries::STAGE_ROUTES,
                vec![],
            ),
            pin(
                "python_env_stage_unplaced_routes",
                super::super::python_unit_summaries::STAGE_UNPLACED_ROUTES,
                vec![],
            ),
        ]);
        queries.extend([
            pin("python_environment_snapshot_inputs", super::super::python_unit_summaries::SNAPSHOT_INPUTS_SQL, vec![text(&"e".repeat(64)),integer(0),integer(1),text(&serde_json::to_string(&brokk_bifrost_python::declarations::PYTHON_CONFIGURATION_INPUT_NAMES).unwrap())]),
            pin("python_environment_source_rows", super::super::python_binding_rows::ENVIRONMENT_SOURCE_SQL, vec![text(&"e".repeat(64)),integer(0),integer(1),integer(super::super::python_binding_rows::NATIVE_SOURCE_FORMAT)]),
            pin("python_owner_member_operations", super::super::python_member_rows::OWNER_OPERATIONS_SQL, vec![integer(super::super::python_binding_rows::NATIVE_SOURCE_FORMAT),text("missing"),integer(1)]),
            pin("python_direct_member_writes", super::super::python_member_rows::DIRECT_MEMBER_WRITES_SQL, vec![integer(super::super::python_binding_rows::NATIVE_SOURCE_FORMAT),text("missing"),integer(1),integer(super::super::resolution_prepare::resolution_rows::code(brokk_bifrost_core::analyzer::resolution_facts::ALL_BINDING_PROJECTION_KINDS,brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetCallableResultType))]),
            pin("python_builtin_namespace_closed", super::super::python_member_rows::BUILTIN_NAMESPACE_CLOSED_SQL, vec![integer(1),integer(1),integer(2)]),
            pin("python_universe_reference_name", super::super::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL, vec![integer(1),integer(1)]),
            pin("python_late_member_operations", super::super::python_member_rows::LATE_OPERATIONS_SQL, vec![integer(super::super::python_binding_rows::NATIVE_SOURCE_FORMAT),text("missing"),integer(1)]),
            pin("python_patch_target_literal", super::super::python_member_rows::PATCH_TARGET_LITERAL_SQL, vec![integer(1),integer(1)]),
            pin("python_member_operations_inventory", "SELECT id FROM python_member_operations WHERE blob_id=?1 AND name_kind=?2 AND effect=?3 ORDER BY site", vec![integer(1),integer(0),integer(1)]),
            pin("python_member_operation_names_lookup", "SELECT operation FROM python_member_operation_names WHERE spelling=?1", vec![text("known42")]),
        ]);
        for (name, sql, params) in [
            (
                "reverse_candidate_keys_ddl",
                super::super::resolution_operation::REVERSE_CANDIDATE_KEYS_DDL,
                vec![],
            ),
            (
                "reverse_candidates",
                super::super::resolution_operation::REVERSE_CANDIDATES_SQL,
                vec![],
            ),
            (
                "reverse_candidate_keys_clear",
                super::super::resolution_operation::REVERSE_CANDIDATE_KEYS_CLEAR_SQL,
                vec![],
            ),
            (
                "reverse_candidate_keys_insert",
                super::super::resolution_operation::REVERSE_CANDIDATE_KEYS_INSERT_SQL,
                vec![text("[[0,0,1,1,1,1,1]]")],
            ),
        ] {
            queries.push(pin(name, sql, params));
        }
        #[cfg(test)]
        queries.push(python_reverse_candidate_pin());
        queries.push(pin(
            "reverse_candidates_with_lookup_inventory",
            super::super::resolution_operation::reverse_candidates_sql(&[
                super::super::resolution_operation::REVERSE_LOOKUP_IDENTITY_ARM_SQL,
            ])
            .into_owned(),
            vec![],
        ));

        queries.push(pin(
            "intrinsic_member_owner_indexed",
            super::super::resolution_typed::external_owners::INTRINSIC_MEMBER_OWNER_INDEXED_SQL,
            vec![text("provider"), text("java.lang.Object")],
        ));
        queries.push(pin(
            "external_member_owner_by_definition",
            super::super::resolution_typed::external_owners::EXTERNAL_MEMBER_OWNER_BY_DEFINITION_SQL,
            vec![text("provider"), text("owner.Type"), integer(0), text("[\"provider\"]")],
        ));
        queries.push(pin(
            "type_productions_by_output",
            super::super::resolution_prepare::typed_rows::TYPE_PRODUCTIONS_BY_OUTPUT_SQL,
            vec![integer(1), text("[1,2,3,4]")],
        ));
        queries.push(pin(
            "php_dynamic_import_sources",
            crate::analyzer::store::import_graph::DYNAMIC_IMPORT_SOURCES_SQL,
            vec![text("[[\"php\",\"src/Dynamic.php\"]]")],
        ));
        queries.push(pin(
            "semantic_ir_publication",
            super::super::semantic_ir::SEMANTIC_IR_PUBLICATION_SQL,
            vec![
                text("5555555555555555555555555555555555555555"),
                text("rust"),
                Value::Blob(Vec::new()),
            ],
        ));
        #[cfg(test)]
        queries.extend(rust_macro_source_row_pins());
        queries.push(pin(
            "selected_macro_occurrence_lines",
            super::super::resolution_operation::SELECTED_MACRO_OCCURRENCE_LINES_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "generic_parameter_declarations",
            super::super::resolution_typed::GENERIC_PARAMETER_DECLARATIONS_SQL,
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "qualified_route_mounts",
            super::super::resolution_typed::QUALIFIED_ROUTE_MOUNTS_SQL,
            vec![integer(
                super::super::resolution::TypedFactRelation::QualifiedRouteLookup.code(),
            )],
        ));
        queries.push(pin(
            "invocation_roles_for_references",
            super::super::resolution_typed::INVOCATION_ROLES_FOR_REFERENCES_SQL,
            vec![integer(1), text("[1,2,3]")],
        ));
        queries.push(pin(
            "go_definition_package_anchor",
            super::super::resolution_operation::native_units::GO_DEFINITION_PACKAGE_ANCHOR,
            vec![integer(1)],
        ));
        queries.push(pin(
            "go_reverse_inventory_complete",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_INVENTORY_COMPLETE_SQL
                .as_str(),
            vec![
                integer(1),
                integer(1),
                integer(1),
                integer(0),
                text("[[1,\"type\"]]"),
                text("workspace"),
                integer(1),
                integer(1),
                text("go-epoch"),
                digest(1),
                integer(3),
                text("[]"),
            ],
        ));
        queries.push(pin(
            "reference_local_path_evidence",
            super::super::resolution_lexical::REFERENCE_LOCAL_PATH_EVIDENCE_SQL,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_reverse_summary_export_rows",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_SUMMARY_EXPORT_ROWS_SQL,
            vec![
                integer(1),
                text("[[1,\"type\"]]"),
                integer(1),
                integer(1),
                text("workspace"),
                integer(1),
                integer(1),
                text("go-epoch"),
                integer(3),
                digest(1),
                text("[[1,1]]"),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_point_binding_receiver_anchor",
            super::super::resolution_operation::go_receiver_anchor::GO_POINT_BINDING_RECEIVER_ANCHOR,
            vec![integer(1), integer(12), integer(16)],
        ));
        queries.push(pin(
            "go_reverse_transient_target_exports",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_TRANSIENT_TARGET_EXPORTS_SQL,
            vec![
                integer(1),
                text("[[1,1]]"),
                text("[[1,\"type\"]]"),
            ],
        ));
        queries.push(pin(
            "go_reverse_transient_alias_exports",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_TRANSIENT_ALIAS_EXPORTS_SQL,
            vec![
                integer(1),
                text("[[1,\"type\"]]"),
                integer(1),
                text("go"),
                integer(1),
                text("workspace"),
                integer(1),
                integer(1),
                text("go-epoch"),
                integer(3),
                digest(1),
                text("[[1,1]]"),
            ],
        ));
        queries.push(pin(
            "go_reverse_qualified_import",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_QUALIFIED_IMPORT_SQL,
            vec![
                integer(1),
                integer(1),
                integer(1),
                text("[[1,\"pkg\"]]"),
                integer(1),
                text("go"),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_reverse_dot_export_rows",
            super::super::resolution_operation::go_reverse_rows::GO_REVERSE_DOT_EXPORT_ROWS_SQL,
            vec![
                integer(1),
                integer(1),
                text("[[1,\"type\"]]"),
                text("workspace"),
                integer(1),
                integer(1),
                text("go-epoch"),
                integer(3),
                digest(1),
                text("[[1,1]]"),
                integer(1),
                integer(1),
                text("go"),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_rename_target_units",
            super::super::resolution_operation::go_reverse_rows::GO_RENAME_TARGET_UNITS_SQL
                .as_str(),
            vec![integer(1), text("src/main.go")],
        ));
        queries.push(pin(
            "go_rename_local_name_conflict",
            super::super::resolution_operation::go_reverse_rows::GO_RENAME_LOCAL_NAME_CONFLICT_SQL,
            vec![text("[[1,1,10]]"), text("[1]")],
        ));
        queries.push(pin(
            "go_rename_edit_site_scope_keys",
            super::super::resolution_operation::go_reverse_rows::GO_RENAME_EDIT_SITE_SCOPE_KEYS_SQL,
            vec![text("[[1,1]]")],
        ));
        queries.push(pin(
            "go_rename_import_name_conflict",
            super::super::resolution_operation::go_reverse_rows::GO_RENAME_IMPORT_NAME_CONFLICT_SQL,
            vec![text("[[1,1]]"), text("[1]")],
        ));
        queries.push(pin(
            "go_rename_package_name_conflict",
            super::super::resolution_operation::go_reverse_rows::GO_RENAME_PACKAGE_NAME_CONFLICT_SQL,
            vec![text("[1]"), text("[1]")],
        ));
        queries.push(pin(
            "go_rename_rebound_root_references",
            super::super::resolution_operation::go_reverse_rows::GO_RENAME_REBOUND_ROOT_REFERENCES_SQL.as_str(),
            vec![
                text("[1]"),
                text("[1]"),
                text("[[1,1]]"),
                text("[[1,1]]"),
                text("len"),
                integer(1),
            ],
        ));
        queries.push(pin(
            "jvm_native_import_target_mounts",
            super::super::resolution_operation::jvm_context::JAVA_IMPORT_TARGET_MOUNTS,
            vec![text("dep")],
        ));
        use super::super::resolution_operation::jvm_context;
        for (language_set, languages) in [
            ("all", [text("java"), text("kotlin"), text("scala")]),
            ("java_peers", [text("kotlin"), text("scala"), Value::Null]),
        ] {
            // Cassandra's two file plans use 60 and 146 distinct names.
            for arity in [1, 60, 146] {
                let names = serde_json::to_string(&(1..=arity).collect::<Vec<_>>()).unwrap();
                let mut params = vec![text("dep"), text(&names)];
                params.extend_from_slice(&languages);
                queries.push(pin(
                    format!("jvm_named_package_member_targets_{language_set}_{arity}"),
                    jvm_context::jvm_named_package_member_targets_sql(),
                    params,
                ));
            }
            let mut params = vec![text("dep")];
            params.extend_from_slice(&languages);
            queries.push(pin(
                format!("jvm_package_member_uncertainty_{language_set}"),
                jvm_context::jvm_package_member_uncertainty_sql(),
                params,
            ));
        }
        for (language_set, languages) in [
            ("all", [text("java"), text("kotlin"), text("scala")]),
            ("java_peers", [text("kotlin"), text("scala"), Value::Null]),
            ("kotlin_peers", [text("java"), text("scala"), Value::Null]),
            ("scala_peers", [text("java"), text("kotlin"), Value::Null]),
        ] {
            let mut params = vec![text("dep")];
            params.extend_from_slice(&languages);
            queries.push(pin(
                format!("jvm_eligible_import_targets_{language_set}"),
                jvm_context::JVM_ELIGIBLE_IMPORT_TARGET_MOUNTS,
                params,
            ));
        }
        queries.push(pin(
            "jvm_package_presence",
            jvm_context::jvm_package_presence_sql(),
            vec![text("dep")],
        ));
        queries.push(pin(
            "jvm_native_alias_member_by_blob",
            super::super::resolution_operation::jvm_context::SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER,
            vec![integer(1), text("member")],
        ));
        queries.push(pin(
            "jvm_preparation_supertype_membership",
            jvm_context::JVM_SUPERTYPE_REFERENCE_MEMBERSHIP,
            vec![integer(1), text("[1,2,3]")],
        ));
        queries.push(pin(
            "import_token_metadata",
            super::super::resolution_operation::imports::IMPORT_TOKEN_METADATA,
            vec![
                integer(1),
                integer(1001),
                integer(1),
                integer(4294968297),
                Value::Null,
            ],
        ));
        queries.push(pin(
            "jvm_native_import_selector",
            super::super::resolution_operation::imports::SELECTED_IMPORT_SELECTOR,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "jvm_native_source_access",
            super::super::resolution_operation::jvm_context::SOURCE_ACCESS,
            vec![
                integer(1),
                integer(1),
                text("consumer/src/main/java/use/Caller.java"),
                integer(2),
                text("provider/src/main/java/dep/Target.java"),
            ],
        ));
        use super::super::resolution_operation::package_context;
        for (name, sql, params) in [
            (
                "native_package_references",
                package_context::ORDINARY_REFERENCES,
                vec![integer(0)],
            ),
            (
                "native_package_members",
                package_context::ORDINARY_MEMBERS,
                vec![integer(1), integer(1)],
            ),
            (
                "native_package_members_by_mount",
                package_context::ORDINARY_MEMBERS_BY_MOUNT,
                vec![integer(1)],
            ),
            (
                "native_stage_package_references",
                package_context::STAGED_PACKAGE_REFERENCES,
                vec![integer(0)],
            ),
            (
                "native_stage_package_members",
                package_context::STAGED_MEMBERS,
                vec![integer(1), integer(1)],
            ),
            (
                "native_stage_package_members_by_mount",
                package_context::STAGED_MEMBERS_BY_MOUNT,
                vec![integer(1)],
            ),
        ] {
            queries.push(pin(name, sql, params));
        }
        for arity in [1_u32, 64, 256] {
            use crate::analyzer::resolution::{SemanticId, SharedNameId};
            let requests = (0..arity)
                .map(|index| {
                    crate::analyzer::store::resolution_stage::lexical::semantic_cells(
                        if index % 2 == 0 {
                            SemanticId::operation_local((1_u64 << 53) + 3000 + u64::from(index))
                        } else {
                            SemanticId::shared_name(SharedNameId::per_request(3000 + index))
                        },
                    )
                })
                .collect::<Vec<_>>();
            queries.push(pin(
                if arity == 1 {
                    "stage_rust_reference_contexts".to_owned()
                } else {
                    format!("stage_rust_reference_contexts_{arity}")
                },
                crate::analyzer::store::resolution_stage::rust_context::REFERENCES_SQL,
                vec![text(
                    &serde_json::to_string(&requests).expect("Rust context request pairs"),
                )],
            ));
            queries.push(pin(format!("stage_lexical_prefix_spellings_{arity}"),
                crate::analyzer::store::resolution_stage::lexical_readers::REFERENCE_LOOKUP_SPELLINGS_SQL,
                vec![
                    text(&serde_json::to_string(&requests).expect("prefix pin parameters")),
                    text(&serde_json::to_string(&crate::analyzer::store::resolution_prepare::reference_lookup_namespace_codes(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
                    )).expect("prefix namespace pin parameters")),
                ],
            ));
            queries.push(pin(format!("stage_go_reference_spellings_{arity}"),
                crate::analyzer::store::resolution_stage::lexical_readers::REFERENCE_LOOKUP_SPELLINGS_SQL,
                vec![
                    text(&serde_json::to_string(&requests).expect("Go spelling pin parameters")),
                    text(&serde_json::to_string(&crate::analyzer::store::resolution_prepare::go_reference_lookup_namespace_codes(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::TypeOrValue,
                    )).expect("Go namespace pin parameters")),
                ],
            ));
        }
        queries.push(pin(
            "selected_typed_shared_membership",
            crate::analyzer::store::resolution_typed::shared_membership_sql(
                1,
                crate::analyzer::store::resolution::TypedFactRelation::DeferredMemberOwnerLookup,
            ),
            vec![integer(0), integer(1)],
        ));
        queries.push(pin(
            "selected_typed_shared_membership_64",
            crate::analyzer::store::resolution_typed::shared_membership_sql(
                64,
                crate::analyzer::store::resolution::TypedFactRelation::DeferredMemberOwnerLookup,
            ),
            (0..64)
                .flat_map(|ordinal| [integer(ordinal), integer(1)])
                .collect(),
        ));
        queries.extend([
            pin(
                "python_runtime_scope_at_path",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_SCOPE_AT_PATH_SQL,
                vec![integer(1), text("src/pkg")],
            ),
            pin(
                "python_runtime_unresolved_scopes",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_UNRESOLVED_SCOPES_SQL,
                vec![integer(1)],
            ),
            pin(
                "python_runtime_import_candidates",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_IMPORT_CANDIDATES_SQL,
                vec![
                    integer(1),
                    integer(7),
                    text("pkg.module"),
                    text(&"a".repeat(64)),
                    text("python"),
                    integer(0),
                    integer(1),
                ],
            ),
            pin(
                "python_runtime_artifacts_for_environment",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_ARTIFACTS_FOR_ENVIRONMENT_SQL,
                vec![integer(7), integer(1)],
            ),
            pin(
                "python_runtime_artifact_members",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_ARTIFACT_MEMBERS_SQL,
                vec![integer(1), integer(9)],
            ),
            pin(
                "python_runtime_scope_frontiers",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_SCOPE_FRONTIERS_SQL,
                vec![integer(1), integer(7), text("pkg.module")],
            ),
            pin(
                "python_runtime_unnamed_scope_frontiers",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_UNNAMED_SCOPE_FRONTIERS_SQL,
                vec![integer(1), integer(7)],
            ),
            pin(
                "python_runtime_declared_environment",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_DECLARED_ENVIRONMENT_SQL,
                vec![integer(1), integer(7)],
            ),
            pin(
                "python_runtime_declared_roots",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_DECLARED_ROOTS_SQL,
                vec![integer(1)],
            ),
            pin(
                "python_runtime_declared_inputs",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_DECLARED_INPUTS_SQL,
                vec![integer(1)],
            ),
            pin(
                "python_runtime_declared_extras",
                crate::analyzer::store::python_runtime::PYTHON_RUNTIME_DECLARED_EXTRAS_SQL,
                vec![integer(1)],
            ),
        ]);
        for arity in [0, 1, 64, 256] {
            queries.push(pin(
                format!("selected_reference_gap_completions_{arity}"),
                crate::analyzer::store::resolution_lexical::reference_gap_completions_sql(),
                vec![
                    integer(0),
                    integer(0),
                    integer(1),
                    text(&serde_json::to_string(&(1..=arity).collect::<Vec<_>>()).unwrap()),
                    integer(crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference)),
                    integer(0),
                ],
            ));
        }
        queries.push(pin(
            "frontier_source_ready",
            crate::analyzer::store::resolution_typed::FRONTIER_SOURCE_READY_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "structural_recovered_regions",
            crate::analyzer::store::STRUCTURAL_RECOVERED_REGIONS_SQL,
            vec![
                integer(1),
                text(&crate::analyzer::store::callable_kind_codes_json()),
            ],
        ));
        queries.push(pin("stage_lexical_ordinary_completion_suppression",
            crate::analyzer::store::resolution_stage::lexical_readers::ORDINARY_COMPLETION_SUPPRESSION_SQL,
            vec![Value::Integer(crate::analyzer::store::resolution_stage::codec::encode_semantic(crate::analyzer::resolution::SemanticId::local(0,0))),
                Value::Integer(crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference))],
        ));
        queries.push(pin(
            "stage_capsule_membership",
            crate::analyzer::store::resolution_stage::CAPSULE_MEMBERSHIP_QUERY,
            vec![Value::Integer(1), Value::Integer(4095)],
        ));
        queries.push(pin(
            "stage_typed_frontiers",
            crate::analyzer::store::resolution_stage::TYPED_FRONTIER_QUERY,
            vec![text("[[17,null]]")],
        ));
        queries.push(pin(
            "stage_typed_observations",
            crate::analyzer::store::resolution_stage::TYPED_OBSERVATION_QUERY,
            vec![text("[[17,null]]")],
        ));
        queries.push(pin(
            "stage_typed_property_gap_reasons",
            crate::analyzer::store::resolution_stage::TYPED_PROPERTY_GAP_REASON_QUERY,
            vec![text("[[17,null]]")],
        ));
        // These are the production batch seeks, including both semantic
        // namespace bindings. The operator context installs the real TEMP DDL.
        for (family, sql, spaces) in [
            (
                "semantics",
                super::super::resolution_stage::allocation::SEMANTICS_SQL,
                &[0, 1][..],
            ),
            (
                "nodes",
                super::super::resolution_stage::allocation::NODES_SQL,
                &[0][..],
            ),
            (
                "paths",
                super::super::resolution_stage::allocation::PATHS_SQL,
                &[0][..],
            ),
        ] {
            for &shared in spaces {
                for arity in [1, 64, 256] {
                    let requests = (0..arity)
                        .map(|key: i64| {
                            let mut digest = [0_u8; 32];
                            digest[..8].copy_from_slice(&key.to_le_bytes());
                            serde_json::json!([
                                1,
                                super::super::resolution_lexical::hex_digest(digest),
                                shared
                            ])
                        })
                        .collect::<Vec<_>>();
                    queries.push(pin(
                        format!("stage_allocation_{family}_{shared}_{arity}"),
                        sql,
                        vec![text(
                            &serde_json::to_string(&requests).expect("allocation pin parameters"),
                        )],
                    ));
                }
            }
        }
        queries.push(pin(
            "rust_impl_children",
            super::super::rust_impl_children::sql(),
            vec![Value::Null; 11],
        ));
        queries.extend(root_terminal_demand_queries());
        queries.extend(
            crate::analyzer::store::rust_crates::sql_pins()
                .into_iter()
                .chain(crate::analyzer::store::resolution_operation::rust_crate_point_sql_pins())
                .map(|(name, sql, parameters)| pin(name, sql, vec![Value::Null; parameters])),
        );
        // Four observed reader shapes: ordinary type/value exports, a macro
        // lookup and a crate-root alias. Use bound values rather than NULL.
        let targets = concat!(
            include_str!("resolution_operation/rust_crate_point_targets.sql"),
            "SELECT topology_id, module_path, name FROM targets"
        );
        for (shape, namespace, module, name) in [
            ("type", "type", "crate", "Item"),
            ("value", "value", "crate::child", "target"),
            ("macro", "macro", "crate::child", "chosen"),
            ("root", "type", "crate", "self"),
        ] {
            queries.push(pin(
                format!("rust_point_targets_{shape}"),
                targets,
                vec![
                    Value::Integer(1),
                    text(module),
                    text(namespace),
                    text(name),
                    Value::Integer(1),
                    text(module),
                ],
            ));
        }
        queries.push(pin(
            "rust_crate_module_walk",
            crate::analyzer::store::rust_crates::MODULE_WALK_SQL,
            vec![text("app/src/lib.rs"), text("[\"test\"]"), text("[]")],
        ));
        queries.push(pin(
            "rust_crate_item_macro_decisions",
            crate::analyzer::store::rust_crates::ITEM_MACRO_DECISIONS_SQL,
            vec![text("[]"), text("[]")],
        ));
        queries.push(pin(
            "rust_crate_collect_unbound",
            crate::analyzer::store::rust_crates::DELETE_UNBOUND_TOPOLOGIES_SQL,
            vec![],
        ));
        // The textual-macro module walk, pinned with a real `rel_path` rather
        // than NULL: these are the statements the index
        // `rust_crate_containers_rel_path` exists for, and what a plan pin has
        // to show about them is that the path is sought and not scanned.
        use crate::analyzer::store::resolution_operation::rust_crate_context as macro_walk;
        queries.extend([
            pin(
                "rust_macro_walk_ancestry",
                macro_walk::MACRO_WALK_ANCESTRY,
                vec![text("[\"app/src/lib.rs\",\"app/src/child.rs\"]")],
            ),
            pin(
                "rust_macro_walk_child_module_files",
                macro_walk::MACRO_WALK_CHILD_MODULE_FILES,
                vec![text("app/src/lib.rs"), text("child")],
            ),
            pin(
                "rust_macro_included_file",
                macro_walk::MACRO_INCLUDED_FILE,
                vec![text("app/src/lib.rs"), text("generated.rs")],
            ),
            pin(
                "rust_macro_include_starts",
                macro_walk::MACRO_INCLUDE_STARTS,
                vec![text("app/src/lib.rs")],
            ),
            pin(
                "rust_macro_host_files",
                macro_walk::MACRO_HOST_FILES,
                vec![text("app/src/generated.rs")],
            ),
        ]);
        use crate::analyzer::store::resolution_operation::rust_reverse_rows as reverse;
        queries.extend([
            pin(
                "rust_reverse_definition_blob",
                crate::analyzer::store::selected_definition::SELECTED_DEFINITION_BLOB_SQL,
                vec![integer(1)],
            ),
            pin(
                "rust_reverse_definition_semantics",
                crate::analyzer::store::selected_definition::DEFINITION_SEMANTICS_SQL.as_str(),
                vec![integer(1)],
            ),
            pin(
                "rust_reverse_base_target_activation",
                reverse::BASE_TARGET_ACTIVATION_SQL,
                vec![integer(1), integer(1)],
            ),
            pin(
                "rust_reverse_masked_blob",
                reverse::MASKED_BLOB_SQL,
                vec![text("src/lib.rs")],
            ),
            pin(
                "rust_reverse_blob_definition_site",
                reverse::BLOB_DEFINITION_SITE_SQL,
                vec![integer(1), integer(1)],
            ),
            pin(
                "rust_reverse_trusted_field_reference",
                reverse::FIELD_REFERENCE_PROVENANCE_SQL,
                vec![
                    text("src/lib.rs"),
                    integer(7),
                    integer(super::super::resolution_prepare::resolution_rows::namespace_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Value,
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::MemberReference,
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::MalformedSyntax,
                        ),
                    )),
                    integer(i64::from(super::super::source_facts::provenance_code(
                        brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode,
                    ))),
                ],
            ),
            pin(
                "rust_reverse_site_cfg",
                reverse::SITE_CFG_SQL,
                vec![text("src/lib.rs"), integer(7)],
            ),
            pin(
                "rust_reverse_macro_textual_closure",
                reverse::MACRO_TEXTUAL_CLOSURE_SQL,
                vec![
                    integer(1),
                    integer(7),
                    text("forward_to_deserialize_any"),
                    integer(1),
                    integer(super::super::source_facts::rust_items::RUST_MACRO_FACTS_VERSION),
                    integer(super::super::source_facts::rust_items::RUST_MACRO_CONTEXTS_VERSION),
                ],
            ),
            pin(
                "rust_reverse_call_arity",
                reverse::CALL_ARITY_SQL,
                vec![integer(1), integer(7)],
            ),
            pin(
                "rust_reverse_call_shape",
                reverse::CALL_SHAPE_SQL,
                vec![
                    text("src/lib.rs"), integer(7), text("[[0,1]]"),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::CallableReference,
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::MemberReference,
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::namespace_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Callable,
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::code(
                        brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_ENGINE_RULE_KINDS,
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionEngineRuleKind::ArgumentCoercionFilter,
                    )),
                    integer(i64::from(super::super::source_facts::provenance_code(
                        brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode,
                    ))),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference,
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedCallApplicability,
                        ),
                    )),
                ],
            ),
            pin(
                "rust_graph_definitions",
                crate::analyzer::store::resolution_operation::RUST_GRAPH_DEFINITIONS_SQL,
                vec![],
            ),
            pin(
                "rust_reverse_caller_roots",
                reverse::CALLER_ROOTS_SQL,
                vec![text("src/lib.rs")],
            ),
            pin(
                "rust_reverse_contract_owner",
                reverse::CONTRACT_OWNER_SQL,
                vec![integer(0), integer(0)],
            ),
            pin(
                "rust_reverse_reference_lookup_blobs",
                reverse::REFERENCE_LOOKUP_BLOBS_SQL,
                vec![digest(0)],
            ),
            pin(
                "rust_reverse_target_activation",
                reverse::BASE_TARGET_ACTIVATION_SQL,
                vec![integer(0), integer(0)],
            ),
            pin(
                "rust_reverse_definition_site",
                reverse::DEFINITION_SITE_SQL,
                vec![integer(0), integer(0)],
            ),
            pin(
                "rust_reverse_root_references",
                reverse::ROOT_REFERENCES_SQL,
                vec![digest(0), text("crate"), text("target")],
            ),
            pin(
                "rust_reverse_imports",
                reverse::IMPORTS_SQL,
                vec![digest(0), text("crate"), text("X")],
            ),
            pin(
                "rust_reverse_globs",
                reverse::GLOBS_SQL,
                vec![digest(0), text("crate")],
            ),
            pin(
                "rust_reverse_module_sources",
                reverse::MODULE_SOURCES_SQL,
                vec![digest(0), text("crate")],
            ),
            pin(
                "rust_reverse_locators",
                reverse::LOCATORS_SQL,
                vec![integer(1)],
            ),
            pin(
                "rust_reverse_textual_macro_sources",
                reverse::TEXTUAL_MACRO_SOURCES_SQL,
                vec![integer(1)],
            ),
            pin(
                "rust_reverse_gap_candidate_sites",
                reverse::GAP_CANDIDATE_SITES_SQL,
                vec![
                    integer(1),
                    text("[[\"target\",\"callable\"]]"),
                    integer(1),
                    text("[1]"),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::MemberReference,
                    )),
                    integer(1),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::CallableReference,
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::MacroArgument,
                        ),
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedItemMacro,
                        ),
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro,
                        ),
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder,
                        ),
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedExpression,
                        ),
                    )),
                    integer(1),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::MalformedSyntax,
                        ),
                    )),
                ],
            ),
            pin(
                "rust_reverse_target_scoped_inventory_gaps",
                reverse::target_scoped_reference_inventory_gaps_sql(),
                vec![
                    integer(1),
                    text("[[\"target\",\"callable\"]]"),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference,
                    )),
                    integer(1 << 31),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::MemberReference,
                    )),
                    text("[]"),
                    integer(1),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::CallableReference,
                    )),
                    text("[]"),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface,
                        ),
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedCallApplicability,
                        ),
                    )),
                ],
            ),
            pin(
                "rust_reverse_initial_gap_locators",
                reverse::initial_reference_inventory_gap_locators_sql(),
                vec![
                    integer(1),
                    text("[[\"target\",\"callable\"]]"),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference,
                    )),
                    integer(1 << 31),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::MemberReference,
                    )),
                    text("[]"),
                    integer(1),
                    integer(super::super::resolution_prepare::resolution_rows::site_kind_code(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::CallableReference,
                    )),
                    text("[]"),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface,
                        ),
                    )),
                    integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedCallApplicability,
                        ),
                    )),
                ],
            ),
        ]);
        queries.extend([
            pin("rust_reverse_exports", include_str!("rust_reverse_exports.sql"), vec![integer(1), integer(0), text("src/lib.rs")]),
            pin("rust_blob_placement_activity", crate::analyzer::store::resolution_operation::rust_crate_access::BLOB_PLACEMENT_ACTIVITY, vec![text("[1,2,3]")]),
            pin("rust_crate_imports_binder", "SELECT * FROM rust_crate_imports WHERE topology_id = ?1 AND module_path = ?2 AND blob_id = ?3 AND binder_scope = ?4 AND bound_name = ?5", vec![integer(1), text("crate"), integer(1), integer(0), text("X")]),
            pin("rust_crate_imports_target", "SELECT * FROM rust_crate_imports WHERE target_crate_key = ?1 AND target_module_path = ?2 AND target_name = ?3", vec![digest(0), text("crate"), text("X")]),
            pin("rust_crate_exports_declaration", "SELECT * FROM rust_crate_exports WHERE declaration_blob_id = ?1 AND declaration_site = ?2", vec![integer(1), integer(0)]),
            pin("rust_crate_glob_reexport_routes_target", "SELECT * FROM rust_crate_glob_reexport_routes WHERE target_crate_key = ?1 AND target_module_path = ?2", vec![digest(0), text("crate")]),
            pin("rust_crate_reexport_routes_target", "SELECT * FROM rust_crate_reexport_routes WHERE target_crate_key = ?1 AND target_module_path = ?2 AND target_name = ?3", vec![digest(0), text("crate"), text("X")]),
            pin("selected_rust_crates", "SELECT * FROM selected_rust_crates WHERE crate_key = ?1", vec![digest(0)]),
            pin("selected_rust_crate_containers", "SELECT * FROM selected_rust_crate_containers WHERE topology_id = ?1 AND container_path = ?2", vec![integer(1), text("crate")]),
            pin("rust_crate_exports_reachable", "SELECT * FROM rust_crate_exports_reachable WHERE topology_id = ?1 AND module_path = ?2 AND name = ?3", vec![integer(1), text("crate"), text("X")]),
        ]);

        // Milestone 6's checkpoint (lane PK). The path read is a primary-key
        // seek and the two identity reads are seeks on `resolution_identities`'
        // own keys, so none of them needs an index of its own or an
        // `INDEXED BY`; what the pins assert is that the JSON array drives the
        // seek instead of being joined against a scan of the table.
        use crate::analyzer::store::resolution_prepare::resolution_rows as rows;
        queries.extend([
            pin(
                "jvm_alias_owner_surface_by_identity",
                crate::analyzer::store::resolution_prepare::authority_rows::NODE_FOR_IDENTITY_SQL,
                vec![integer(1), digest(0)],
            ),
            pin(
                "jvm_alias_stage_owner_surface_by_identity",
                crate::analyzer::store::resolution_stage::lexical_readers::NODE_IDENTITIES_SQL,
                vec![text(
                    r#"[[0,"0000000000000000000000000000000000000000000000000000000000000000"]]"#,
                )],
            ),
            pin(
                "resolution_paths_by_key",
                rows::RESOLUTION_PATHS_BY_KEY_SQL,
                vec![integer(1), text("[0]")],
            ),
            pin(
                "resolution_identity_recipes",
                rows::RESOLUTION_IDENTITY_RECIPES_SQL,
                vec![text(
                    "[\"0000000000000000000000000000000000000000000000000000000000000000\"]",
                )],
            ),
        ]);

        // Port block 2 (lane CM). The two candidate-match statements name
        // their index, because the planner has no statistics on a cache that
        // has not been `ANALYZE`d and would otherwise take the primary-key
        // prefix and scan the blob (lane LD). The site read is a primary-key
        // seek and the member-scope read uses the unique index that table
        // already carries, so neither needs one.
        queries.extend([
            pin(
                "resolution_forward_candidate_match",
                rows::RESOLUTION_FORWARD_CANDIDATE_MATCH_SQL,
                vec![
                    integer(1),
                    text("[[0,0,1,null,0]]"),
                    text("[[0,0]]"),
                    text("[]"),
                ],
            ),
            pin(
                "resolution_reverse_candidate_match",
                rows::RESOLUTION_REVERSE_CANDIDATE_MATCH_SQL,
                vec![
                    integer(1),
                    text("[[0,0,1,null,0]]"),
                    text("[[0,0]]"),
                    text("[]"),
                    text("[[0,\"[[0,null,0]]\",0,1,[1]]]"),
                    text("[]"),
                ],
            ),
            pin(
                "resolution_root_terminal_paths",
                rows::RESOLUTION_ROOT_TERMINAL_PATHS_SQL,
                vec![integer(1), integer(1)],
            ),
            pin(
                "resolution_sites_by_key",
                rows::RESOLUTION_SITES_BY_KEY_SQL,
                vec![integer(1), text("[0]")],
            ),
            pin(
                "resolution_scope_owners_by_node",
                crate::analyzer::store::resolution_lexical::SCOPE_OWNERS_BY_NODE_SQL,
                vec![integer(1), text("[0]")],
            ),
            pin(
                "resolution_member_scope_owners_by_node",
                crate::analyzer::store::resolution_lexical::MEMBER_SCOPE_OWNERS_BY_NODE_SQL,
                vec![integer(1), text("[0]")],
            ),
        ]);
        for arity in [1, 32, 256] {
            queries.push(pin(
                format!("ordinary_reference_sites_by_key_{arity}"),
                crate::analyzer::store::resolution_lexical::REFERENCE_SITES_BY_KEY_SQL,
                vec![
                    integer(1),
                    text(&serde_json::to_string(&(1..=arity).collect::<Vec<_>>()).unwrap()),
                ],
            ));
        }
        // Batch typed readers bind a blob and a JSON key array. Scalar
        // ownership readers carry their exact integer binding shape below.
        // Both families must seek the stored table or its named index.
        use crate::analyzer::store::resolution_prepare::typed_rows as typed;
        for (name, sql) in TYPED_FACT_PINS {
            queries.push(pin(*name, *sql, vec![integer(1), text("[0]")]));
        }
        for (name, sql, keys) in TYPED_OWNER_PINS {
            queries.push(pin(
                *name,
                *sql,
                keys.iter().copied().map(integer).collect(),
            ));
        }
        queries.push(pin(
            "resolution_qualified_routes_by_slot_lookup",
            typed::QUALIFIED_ROUTES_BY_SLOT_LOOKUP_SQL,
            vec![integer(1), text("[[0,0]]")],
        ));
        queries.push(pin(
            "resolution_qualified_routes_inventory",
            typed::QUALIFIED_ROUTES_INVENTORY_SQL,
            vec![integer(1)],
        ));

        let metadata_columns = signature_metadata_projection_columns_sql("metadata");
        queries.push(pin(
            "signature_metadata_batch_reader",
            format!(
                "SELECT keys.blob_oid, metadata.unit_key, {metadata_columns}
                 FROM blobs AS keys
                 JOIN unit_signature_metadata_values AS metadata ON metadata.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.parse_variant = ? AND keys.blob_oid IN (?, ?)
                 ORDER BY keys.blob_oid, metadata.unit_key, metadata.ordinal"
            ),
            vec![text("java"), Value::Blob(Vec::new()), text(OID), text(OID)],
        ));
        queries.push(pin(
            "signature_metadata_for_unit_limited",
            signature_metadata_for_unit_sql(),
            vec![
                text(OID),
                text("java"),
                Value::Blob(Vec::new()),
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
            vec![text(OID), text("rust"), Value::Blob(Vec::new())],
        ));

        // The manifest lookup is the hydration path's only statement that
        // joins and subqueries instead of seeking one primary key.
        queries.push(pin(
            "structural_fact_manifest",
            structural_fact_manifest_sql(),
            vec![text(OID), text("java"), Value::Blob(Vec::new()), integer(1)],
        ));

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
        let langs = vec!["cpp".to_string(), "cpp:c".to_string()];
        for (label, required) in [
            ("cpp_search_owner_name_rows_unfiltered", None),
            (
                "cpp_search_owner_name_rows_prefiltered",
                Some(vec![vec!["owner".to_string(), "run".to_string()]]),
            ),
        ] {
            let (sql, literals) = cpp_search_owner_name_rows_sql(&langs, required.as_deref(), 0);
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
            vec![text("java"), text(OID), Value::Blob(Vec::new()), integer(0)],
        ));

        queries.push(pin(
            "read_path_parsed_blob_membership",
            parsed_blob_keys_sql(2, "", read_path_parsed_blob_condition()),
            vec![Value::Null; 6],
        ));

        let chunk = ["a".to_string(), "b".to_string()];
        queries.push(pin(
            "ranges_bulk",
            ranges_bulk_sql(&chunk_placeholders(&chunk)),
            chunk_params(
                &super::super::BlobKey::unvaried(git2::Oid::from_str(OID).unwrap(), "rust"),
                &chunk,
            ),
        ));

        for (label, sql) in [
            ("exact_path_symbol_fqn", EXACT_PATH_SYMBOL_FQN_SQL),
            ("normalized_path_symbol_fqn", NORMALIZED_PATH_SYMBOL_FQN_SQL),
        ] {
            queries.push(pin(label, sql, vec![text("python"), text("pkg.service")]));
        }

        queries.push(pin(
            "stage_go_definition_namespaces",
            super::super::resolution_stage::lexical_readers::GO_DEFINITION_NAMESPACES_SQL,
            vec![text("[1]")],
        ));

        queries.push(pin(
            "go_dot_import_target_mounts",
            super::super::resolution_operation::go_context::DOT_IMPORT_TARGET_MOUNTS.as_str(),
            vec![
                integer(1),
                integer(1),
                text("go"),
                text("example.test/provider"),
            ],
        ));

        for (label, sql) in [
            (
                "go_named_import_bindings",
                super::super::resolution_operation::go_named::ORDINARY_IMPORT_BINDINGS,
            ),
            (
                "go_named_stage_import_bindings",
                super::super::resolution_operation::go_named::STAGED_IMPORT_BINDINGS,
            ),
        ] {
            queries.push(pin(label, sql, vec![text("[1]")]));
        }
        queries.push(pin(
            "go_file_import_rows",
            super::super::resolution_operation::go_named::GO_FILE_IMPORT_ROWS.as_str(),
            vec![integer(1), text(r#"[[1,1,"go"]]"#)],
        ));
        queries.push(pin(
            "go_named_import_target_mounts",
            super::super::resolution_operation::go_named::NAMED_IMPORT_TARGET_MOUNTS,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "jvm_access_endpoints",
            super::super::resolution_typed::java_access::JVM_ENDPOINTS,
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "scala_reference_endpoints",
            super::super::resolution_typed::java_access::SCALA_REFERENCE_ENDPOINTS,
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "selected_declaration_units",
            super::super::selected_definition::SELECTED_DECLARATION_UNITS_SQL.as_str(),
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "java_access_endpoints",
            super::super::resolution_typed::java_access::ENDPOINTS,
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "go_member_declarations",
            super::super::resolution_typed::go_members::DECLARATIONS,
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "java_inheritance_declarations",
            super::super::resolution_typed::java_inheritance::DECLARATIONS,
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "java_synthetic_type_bodies",
            super::super::resolution_typed::java_inheritance::SYNTHETIC_TYPE_BODIES,
            vec![
                text("[[0,0]]"),
                integer(super::super::code_unit_kind_to_i64(
                    crate::analyzer::CodeUnitType::Class,
                )),
            ],
        ));
        queries.push(pin(
            "go_caller_source_role",
            super::super::resolution_operation::go_named::CALLER_SOURCE_ROLE.as_str(),
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_caller_package",
            super::super::resolution_operation::go_same_package::CALLER_PACKAGE.as_str(),
            vec![integer(1), integer(1), text("go")],
        ));
        queries.push(pin(
            "go_package_peer_mounts",
            super::super::resolution_operation::go_same_package::PACKAGE_PEER_MOUNTS,
            vec![integer(1), integer(1), text("go")],
        ));

        queries.push(pin(
            "go_native_selected_context",
            super::super::go_package_context::SELECT_CONTEXT_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
                digest(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_native_canonical_source",
            super::super::go_package_context::CANONICAL_SOURCE_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                text("consumer/use.go"),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_native_module_manifests",
            super::super::go_package_context::MODULE_MANIFESTS_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_native_source_inventory",
            super::super::go_package_context::SOURCE_INVENTORY_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_native_prior_heads",
            super::super::go_package_context::PRIOR_HEADS_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_native_context_head",
            super::super::go_package_context::RECHECK_CONTEXT_SQL,
            vec![integer(1), integer(1), digest(1), integer(1)],
        ));
        queries.push(pin(
            "go_native_observed_inputs",
            super::super::go_package_context::OBSERVE_INPUTS_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "go_native_refused_inputs",
            super::super::go_package_context::REFUSED_INPUTS_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                integer(1),
                integer(1),
            ],
        ));

        queries.push(pin(
            "selected_dependency_file_evidence",
            super::super::dependency_file_evidence::READ_ROWS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "selected_configuration_bytes",
            super::super::workspace_inputs::SELECTED_CONFIGURATION_BYTES_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                text("java"),
                integer(1),
                text("gradle.properties"),
                integer(1),
            ],
        ));
        queries.push(pin(
            "csharp_compilation_metadata",
            super::super::csharp_compilation::COMPILATION_METADATA_SQL,
            vec![integer(1), text("Proj2/Proj2.csproj")],
        ));
        queries.push(pin(
            "csharp_selected_set",
            super::super::csharp_compilation::SELECTED_SET_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                text("csharp"),
                integer(1),
                integer(1),
            ],
        ));
        queries.push(pin(
            "csharp_selected_source",
            super::super::csharp_compilation::SELECTED_SOURCE_SQL,
            vec![
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                text("csharp"),
                integer(1),
                text("App/Sub/Thing.cs"),
                integer(1),
            ],
        ));
        // Configuration rows are compilation-keyed, separate from per-blob
        // tier-one resolution families. Exercise every new stored column.
        queries.push(pin(
            "csharp_compilation_symbol_environment",
            "SELECT c.configuration, c.target_framework, c.symbols_closed, c.open_reason, c.symbol_set_digest, s.symbol, s.source FROM csharp_compilations c LEFT JOIN csharp_compilation_symbols s ON s.compilation_id = c.compilation_id WHERE c.compilation_id = ?1",
            vec![integer(1)],
        ));
        queries.push(pin(
            "csharp_implicit_compilation",
            super::super::csharp_compilation::IMPLICIT_COMPILATION_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "csharp_path_items",
            super::super::csharp_compilation::PATH_ITEMS_SQL,
            vec![integer(1), text("App/Sub/Thing.cs")],
        ));
        queries.push(pin(
            "csharp_reference_closure",
            super::super::csharp_compilation::REFERENCE_CLOSURE_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "csharp_tree_items",
            super::super::csharp_compilation::TREE_ITEMS_SQL,
            vec![integer(1), text(r#"["","App","App/Sub"]"#)],
        ));
        queries.push(pin(
            "csharp_project_count",
            super::super::csharp_compilation::PROJECT_COUNT_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "csharp_visible_closure",
            super::super::csharp_compilation::VISIBLE_CLOSURE_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "csharp_unselected_include",
            super::super::csharp_compilation::UNSELECTED_INCLUDE_SQL,
            vec![
                integer(1),
                text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                text("csharp"),
                integer(1),
                integer(1),
            ],
        ));

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
                Value::Blob(Vec::new()),
                text(OID),
                text("java"),
                Value::Blob(Vec::new()),
                text(OID),
                text("java"),
                Value::Blob(Vec::new()),
            ],
        ));
        queries.push(pin(
            "persisted_blob_mutation_cost_fallback",
            persisted_blob_mutation_cost_fallback_sql(),
            vec![text(OID), text("java"), Value::Blob(Vec::new())],
        ));
        queries.push(pin(
            "class_set_summary_cascade_costs",
            stored_blob_cascade_costs_sql(1),
            vec![text(OID), text("python"), Value::Blob(Vec::new())],
        ));

        for (name, sql, params) in [
            (
                "class_set_field_slot_index",
                CLASS_SET_FIELD_SLOT_INDEX_SQL,
                vec![
                    text("python"),
                    digest(1),
                    digest(2),
                    digest(3),
                    digest(4),
                    integer(1),
                ],
            ),
            (
                "class_set_field_slots",
                CLASS_SET_FIELD_SLOTS_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_field_slot_stores",
                CLASS_SET_FIELD_SLOT_STORES_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_field_slot_atoms",
                CLASS_SET_FIELD_SLOT_ATOMS_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_field_slot_artifacts",
                CLASS_SET_FIELD_SLOT_ARTIFACTS_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "prune_old_class_set_field_slot_indexes",
                PRUNE_OLD_CLASS_SET_FIELD_SLOT_INDEXES_SQL,
                vec![text("python")],
            ),
            (
                "class_set_root_result_header",
                CLASS_SET_ROOT_RESULT_HEADER_SQL.as_str(),
                vec![
                    text("python"),
                    digest(1),
                    digest(2),
                    digest(3),
                    digest(4),
                    digest(5),
                    integer(1),
                    digest(6),
                    text("python"),
                ],
            ),
            (
                "class_set_root_result_rows",
                CLASS_SET_ROOT_RESULT_ROWS_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "prune_old_class_set_root_result_generations",
                PRUNE_OLD_CLASS_SET_ROOT_RESULT_GENERATIONS_SQL,
                vec![text("python")],
            ),
            (
                "class_set_summary_lookup",
                CLASS_SET_SUMMARY_LOOKUP_SQL.as_str(),
                vec![digest(1)],
            ),
            (
                "class_set_summary_family",
                CLASS_SET_SUMMARY_FAMILY_SQL.as_str(),
                vec![
                    digest(1),
                    text("src/app.py"),
                    text("python"),
                    text("python"),
                    integer(1),
                    digest(2),
                    digest(3),
                    digest(4),
                    digest(5),
                    digest(6),
                    digest(7),
                    integer(2),
                ],
            ),
            (
                "class_set_procedure_surface_family",
                CLASS_SET_PROCEDURE_SURFACE_FAMILY_SQL.as_str(),
                vec![
                    digest(1),
                    text("src/app.py"),
                    text("python"),
                    text("python"),
                    integer(1),
                    digest(2),
                    digest(3),
                    integer(2),
                ],
            ),
            (
                "class_set_procedure_surface_digest",
                CLASS_SET_PROCEDURE_SURFACE_DIGEST_SQL.as_str(),
                vec![digest(1)],
            ),
            (
                "class_set_procedure_surface_calls",
                SURFACE_CALLS_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_procedure_surface_bindings",
                SURFACE_BINDINGS_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_procedure_surface_entered",
                SURFACE_ENTERED_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_procedure_surface_lexical_children",
                SURFACE_LEXICAL_CHILDREN_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_procedure_surface_reads",
                SURFACE_READS_SQL,
                vec![integer(0), integer(2)],
            ),
            (
                "class_set_summary_procedure",
                CLASS_SET_SUMMARY_PROCEDURE_SQL.as_str(),
                vec![digest(2), text("python")],
            ),
            (
                "class_set_summary_dependents_by_lookup",
                CLASS_SET_SUMMARY_DEPENDENTS_BY_LOOKUP_SQL.as_str(),
                vec![digest(14)],
            ),
            (
                "class_set_summary_dependents_by_lineage_entry",
                CLASS_SET_SUMMARY_DEPENDENTS_BY_LINEAGE_ENTRY_SQL.as_str(),
                vec![digest(11), digest(12)],
            ),
            (
                "class_set_summary_dependents_by_read",
                CLASS_SET_SUMMARY_DEPENDENTS_BY_READ_SQL.as_str(),
                vec![digest(1)],
            ),
            ("class_set_summary_facts", FACTS_SQL, vec![integer(0)]),
            ("class_set_summary_exits", EXITS_SQL, vec![integer(0)]),
            ("class_set_summary_reached", REACHED_SQL, vec![integer(0)]),
            (
                "class_set_summary_dependencies",
                DEPENDENCIES_SQL,
                vec![integer(0)],
            ),
            (
                "class_set_summary_dependency_sources",
                DEPENDENCY_SOURCES_SQL,
                vec![integer(0)],
            ),
            ("class_set_summary_reads", READS_SQL, vec![integer(0)]),
            ("class_set_summary_charges", CHARGES_SQL, vec![integer(0)]),
        ] {
            queries.push(pin(name, sql, params));
        }

        for arity in [1usize, 16, 64, 256, 400] {
            queries.push(pin(
                format!("candidate_fq_segments_{arity}"),
                candidate_fq_segments_sql(arity),
                vec![Value::Null; arity * 5],
            ));
        }
        queries.push(pin(
            "raw_unit_fq_segments",
            raw_unit_fq_segments_sql("?, ?"),
            vec![text("java"), Value::Blob(Vec::new()), text(OID), text(OID)],
        ));

        queries.push(pin(
            "limited_identifier_candidate_for_blob",
            format!("{} LIMIT ?5", limited_identifier_candidate_for_blob_sql()),
            vec![
                text("rust"),
                text("Widget"),
                text(OID),
                Value::Blob(Vec::new()),
                integer(16),
            ],
        ));
        queries.push(pin(
            "limited_identifier_candidate",
            limited_identifier_candidate_sql(),
            vec![],
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
        for arity in DEFINITION_CANDIDATE_ARITY_LADDER {
            queries.push(pin(
                format!("batch_component_definition_candidate_{arity}"),
                batch_component_definition_candidate_sql(
                    true,
                    RenderedTailMatch::Exact,
                    MEMBERSHIP,
                ),
                vec![
                    text(&definition_request_payload(arity, false)),
                    text("java"),
                    integer(0),
                ],
            ));
            queries.push(pin(
                format!("batch_stable_component_definition_candidate_{arity}"),
                batch_component_definition_candidate_sql(
                    false,
                    RenderedTailMatch::Exact,
                    MEMBERSHIP,
                ),
                vec![
                    text(&definition_request_payload(arity, false)),
                    text("java"),
                    integer(0),
                ],
            ));
            queries.push(pin(
                format!("batch_anchor_only_definition_candidate_{arity}"),
                batch_anchor_only_definition_candidate_sql(MEMBERSHIP),
                vec![
                    text(&definition_request_payload(arity, true)),
                    text("java"),
                    integer(0),
                ],
            ));
        }
        queries.push(pin(
            "direct_children_limited_candidate",
            direct_children_limited_candidate_sql(),
            vec![
                text(OID),
                text("scala"),
                Value::Blob(Vec::new()),
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
            "mounted_declaration_scan_with_primary_ranges",
            mounted_declaration_sql_with_primary_ranges(),
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
                "SELECT {} FROM source_import_statements
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND parse_variant = ?3)
                 ORDER BY ordinal",
                super::super::IMPORT_STATEMENT_COLUMNS
            ),
            vec![text(OID), text("rust"), Value::Blob(Vec::new())],
        ));
        queries.push(pin(
            "index_digest_blob",
            super::super::INDEX_DIGEST_BLOB_SQL,
            vec![text(OID), text("java"), integer(0)],
        ));
        queries.push(pin(
            "index_digest_units",
            super::super::INDEX_DIGEST_UNITS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_segments",
            super::super::INDEX_DIGEST_SEGMENTS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_ranges",
            super::super::INDEX_DIGEST_RANGES_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_children",
            super::super::INDEX_DIGEST_CHILDREN_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_supertypes",
            super::super::INDEX_DIGEST_SUPERTYPES_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_imports",
            super::super::INDEX_DIGEST_IMPORTS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_import_partitions",
            super::super::INDEX_DIGEST_IMPORT_PARTITIONS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_signatures",
            super::super::INDEX_DIGEST_SIGNATURES_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_metadata",
            super::super::INDEX_DIGEST_METADATA_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_pairings",
            super::super::INDEX_DIGEST_PAIRINGS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "index_digest_readiness",
            super::super::INDEX_DIGEST_READINESS_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "workspace_content_package_facts",
            workspace_content_package_facts_sql(2),
            vec![text("java"), Value::Blob(Vec::new()), text(OID), text(OID)],
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
        queries.push(pin(
            "selected_rust_declaration_authority",
            selected_rust_declaration_authority_sql(2),
            vec![integer(0), integer(11), integer(0), integer(17)],
        ));
        queries.push(pin(
            "jvm_native_alias_declaration_gaps",
            SELECTED_JVM_ALIAS_DECLARATION_GAPS,
            vec![
                integer(1),
                integer(17),
                integer(super::super::resolution_prepare::resolution_rows::gap_origin_code(
                    crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder,
                    ),
                )),
            ],
        ));
        queries.push(pin(
            "selected_definition_units",
            super::super::selected_definition::SELECTED_DEFINITION_UNITS_SQL.as_str(),
            vec![text("[[0,0]]")],
        ));
        queries.push(pin(
            "selected_lexical_definitions",
            super::super::selected_definition::SELECTED_LEXICAL_DEFINITIONS_SQL,
            vec![text("[[0,0]]")],
        ));

        let pair_count = crate::analyzer::store::import_graph::IMPORT_GRAPH_PATH_BATCH;
        let mut pair_params = Vec::with_capacity(pair_count * 2 + 1);
        pair_params.push(text("publication-workspace"));
        for index in 0..pair_count {
            pair_params.push(text(&format!("src/module_{index}.rs")));
            pair_params.push(text("src/lib.rs"));
        }
        queries.push(pin(
            "import_graph_publish_select_existing_edge_pairs_256",
            crate::analyzer::store::import_graph::existing_edge_pairs_sql(pair_count),
            pair_params.clone(),
        ));
        queries.push(pin(
            "import_graph_publish_select_edge_pairs_with_facts_256",
            crate::analyzer::store::import_graph::edge_pairs_with_facts_sql(pair_count),
            pair_params[1..]
                .iter()
                .cloned()
                .chain(std::iter::once(text("publication-workspace")))
                .collect(),
        ));
        queries.push(pin(
            "import_graph_publish_delete_exact_edge_pairs_256",
            crate::analyzer::store::import_graph::delete_edge_pairs_sql(pair_count),
            pair_params.clone(),
        ));
        let mut insert_pair_params = Vec::with_capacity(pair_count * 3);
        for index in 0..pair_count {
            insert_pair_params.push(text("publication-workspace"));
            insert_pair_params.push(text(&format!("src/module_{index}.rs")));
            insert_pair_params.push(text("src/lib.rs"));
        }
        queries.push(pin(
            "import_graph_publish_insert_new_edge_pairs_256",
            crate::analyzer::store::import_graph::insert_edge_pairs_sql(pair_count),
            insert_pair_params,
        ));
        let ordinal_count = crate::analyzer::store::import_graph::IMPORT_GRAPH_ORDINAL_BATCH;
        let mut ordinal_params = Vec::with_capacity(ordinal_count * 2 + 1);
        ordinal_params.push(text("publication-workspace"));
        for index in 0..ordinal_count {
            ordinal_params.push(text(&format!("src/module_{index}.rs")));
            ordinal_params.push(integer(0));
        }
        queries.push(pin(
            "import_graph_publish_select_edge_facts_by_ordinals_256",
            crate::analyzer::store::import_graph::edge_fact_rows_by_ordinals_sql(ordinal_count),
            ordinal_params.clone(),
        ));
        let edge_fact_key_count = crate::analyzer::store::import_graph::IMPORT_GRAPH_ROW_BATCH;
        let mut edge_fact_key_params = Vec::with_capacity(1 + edge_fact_key_count * 3);
        edge_fact_key_params.push(text("publication-workspace"));
        for index in 0..edge_fact_key_count {
            edge_fact_key_params.push(text(&format!("src/module_{index}.rs")));
            edge_fact_key_params.push(integer(0));
            edge_fact_key_params.push(text("src/lib.rs"));
        }
        queries.push(pin(
            "import_graph_publish_delete_stale_edge_facts_64",
            crate::analyzer::store::import_graph::delete_edge_fact_keys_sql(edge_fact_key_count),
            edge_fact_key_params.clone(),
        ));
        let mut edge_fact_upsert_params = Vec::with_capacity(edge_fact_key_count * 5);
        for index in 0..edge_fact_key_count {
            edge_fact_upsert_params.push(text("publication-workspace"));
            edge_fact_upsert_params.push(text(&format!("src/module_{index}.rs")));
            edge_fact_upsert_params.push(integer(0));
            edge_fact_upsert_params.push(text("src/lib.rs"));
            edge_fact_upsert_params.push(text("[]"));
        }
        queries.push(pin(
            "import_graph_publish_upsert_edge_facts_64",
            crate::analyzer::store::import_graph::upsert_edge_facts_sql(edge_fact_key_count),
            edge_fact_upsert_params,
        ));
        for (name, table) in [
            (
                "import_graph_publish_select_candidate_dependencies_by_ordinals_256",
                "workspace_import_candidate_file_dependencies",
            ),
            (
                "import_graph_publish_select_route_dependencies_by_ordinals_256",
                "workspace_import_route_dependencies",
            ),
            (
                "import_graph_publish_select_missing_dependencies_by_ordinals_256",
                "workspace_import_missing_module_dependencies",
            ),
        ] {
            queries.push(pin(
                name,
                crate::analyzer::store::import_graph::import_graph_dependency_rows_by_ordinals_sql(
                    table,
                    ordinal_count,
                ),
                ordinal_params.clone(),
            ));
        }
        let dependency_row_count = crate::analyzer::store::import_graph::IMPORT_GRAPH_ROW_BATCH;
        for (name, table) in [
            (
                "import_graph_publish_delete_candidate_dependency_rows_64",
                "workspace_import_candidate_file_dependencies",
            ),
            (
                "import_graph_publish_delete_route_dependency_rows_64",
                "workspace_import_route_dependencies",
            ),
            (
                "import_graph_publish_delete_missing_dependency_rows_64",
                "workspace_import_missing_module_dependencies",
            ),
        ] {
            let mut params = Vec::with_capacity(
                1 + dependency_row_count
                    * if table == "workspace_import_missing_module_dependencies" {
                        3
                    } else {
                        4
                    },
            );
            params.push(text("publication-workspace"));
            for index in 0..dependency_row_count {
                params.push(text(&format!("src/module_{index}.rs")));
                params.push(integer(0));
                if table == "workspace_import_missing_module_dependencies" {
                    params.push(text(&format!("demo::missing_{index}")));
                } else {
                    params.push(text(&format!("src/module_{index}.rs")));
                    params.push(text("Widget"));
                }
            }
            queries.push(pin(
                name,
                crate::analyzer::store::import_graph::delete_import_graph_dependency_rows_sql(
                    table,
                    dependency_row_count,
                ),
                params,
            ));
        }
        let importer_count = crate::analyzer::store::import_graph::IMPORT_GRAPH_PATH_BATCH;
        let mut importer_params = Vec::with_capacity(importer_count + 1);
        importer_params.push(text("publication-workspace"));
        importer_params
            .extend((0..importer_count).map(|index| text(&format!("src/module_{index}.rs"))));
        queries.push(pin(
            "import_graph_publish_select_edge_fact_keys_by_importers_256",
            crate::analyzer::store::import_graph::edge_fact_rows_by_importers_sql(importer_count),
            importer_params.clone(),
        ));
        for (name, table) in [
            (
                "import_graph_publish_delete_candidate_dependencies_by_importers_256",
                "workspace_import_candidate_file_dependencies",
            ),
            (
                "import_graph_publish_delete_route_dependencies_by_importers_256",
                "workspace_import_route_dependencies",
            ),
            (
                "import_graph_publish_delete_missing_dependencies_by_importers_256",
                "workspace_import_missing_module_dependencies",
            ),
        ] {
            queries.push(pin(
                name,
                crate::analyzer::store::import_graph::delete_importers_sql(table, importer_count),
                importer_params.clone(),
            ));
        }
        let mut removed_sources_params = Vec::with_capacity(importer_count + 1);
        removed_sources_params.push(text("publication-workspace"));
        removed_sources_params
            .extend((0..importer_count).map(|index| text(&format!("src/module_{index}.rs"))));
        for (name, path_column) in [
            (
                "import_graph_publish_select_edge_facts_by_importer_paths_256",
                "importer_path",
            ),
            (
                "import_graph_publish_select_edge_facts_by_target_paths_256",
                "target_path",
            ),
        ] {
            queries.push(pin(
                name,
                crate::analyzer::store::import_graph::edge_fact_pairs_by_paths_sql(
                    path_column,
                    importer_count,
                ),
                removed_sources_params.clone(),
            ));
        }
        queries.push(pin(
            "import_graph_publish_delete_edge_facts_by_removed_targets_256",
            crate::analyzer::store::import_graph::delete_edge_facts_by_target_paths_sql(
                importer_count,
            ),
            removed_sources_params.clone(),
        ));
        for (name, sql) in [
            (
                "import_graph_publish_delete_source",
                "DELETE FROM workspace_import_sources WHERE workspace_id = ?1 AND source_path = ?2",
            ),
            (
                "import_graph_publish_delete_source_modules",
                "DELETE FROM workspace_import_source_modules WHERE workspace_id = ?1 AND source_path = ?2",
            ),
            (
                "import_graph_publish_delete_source_bindings",
                "DELETE FROM workspace_import_source_bindings WHERE workspace_id = ?1 AND source_path = ?2",
            ),
        ] {
            queries.push(pin(
                name,
                sql,
                vec![text("publication-workspace"), text("src/lib.rs")],
            ));
        }
        // The per-unit summary readers and the writer's hooks (derivation
        // contract kind 2). A STAT4 build plans from the bound values, so the
        // workspace id, unit key and epoch are shaped like production's; the pin
        // test in `resolution_operation_unit_summary_tests.rs` rebinds them to
        // the rows of a real Go store.
        queries.push(pin(
            "unit_summary_live_version",
            super::super::go_unit_summaries::GO_LIVE_SUMMARY_SQL,
            vec![
                text(&"7".repeat(64)),
                text("go"),
                integer(1),
                digest(1),
                integer(1),
                text("go-resolution-epoch"),
                integer(1),
                digest(2),
                digest(3),
            ],
        ));
        for (name, sql, params) in [
            (
                "unit_summary_open_version",
                super::super::unit_summaries::OPEN_VERSION_SQL,
                vec![
                    text(&"7".repeat(64)),
                    text("go"),
                    integer(1),
                    digest(1),
                    digest(3),
                ],
            ),
            (
                "unit_summary_close_version",
                super::super::unit_summaries::CLOSE_VERSION_SQL,
                vec![
                    text(&"7".repeat(64)),
                    text("go"),
                    integer(1),
                    digest(1),
                    integer(1),
                    digest(3),
                ],
            ),
            (
                "unit_summary_withdraw_version",
                super::super::unit_summaries::WITHDRAW_VERSION_SQL,
                vec![
                    text(&"7".repeat(64)),
                    text("go"),
                    integer(1),
                    digest(1),
                    integer(1),
                    digest(3),
                ],
            ),
            (
                "unit_summary_withdraw_unsettled",
                super::super::unit_summaries::WITHDRAW_UNSETTLED_SQL,
                vec![
                    text(&"7".repeat(64)),
                    text("go"),
                    integer(1),
                    integer(1),
                    digest(3),
                ],
            ),
            (
                "unit_summary_close_unsettled",
                super::super::unit_summaries::CLOSE_UNSETTLED_SQL,
                vec![
                    text(&"7".repeat(64)),
                    text("go"),
                    integer(1),
                    integer(1),
                    digest(3),
                ],
            ),
            (
                "unit_summary_later_open_version",
                super::super::unit_summaries::LATER_OPEN_VERSION_SQL,
                vec![
                    text(&"7".repeat(64)),
                    text("go"),
                    integer(1),
                    integer(1),
                    digest(3),
                ],
            ),
        ] {
            queries.push(pin(name, sql, params));
        }
        queries.push(pin(
            "unit_summary_export_point",
            super::super::unit_summaries::UNIT_EXPORT_POINT_SQL,
            vec![integer(1), text("value"), integer(1)],
        ));
        queries.push(pin(
            "unit_summary_dependents",
            super::super::unit_summaries::UNIT_DEPENDENTS_SQL,
            vec![
                digest(1),
                text(&"7".repeat(64)),
                text("go"),
                integer(1),
                digest(3),
            ],
        ));
        queries.push(pin(
            "rust_unit_summary_live_version",
            super::super::unit_summaries::LIVE_SUMMARY_SQL,
            vec![
                text(&"7".repeat(64)),
                text("rust"),
                integer(1),
                digest(1),
                integer(1),
                text("rust-resolution-epoch"),
                integer(super::super::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION),
            ],
        ));
        queries.push(pin(
            "rust_unit_summary_dependency_reexport_witness",
            super::super::rust_unit_summaries::DEPENDENCY_REEXPORT_WITNESS_SQL,
            vec![
                text(&"7".repeat(64)),
                text("rust"),
                integer(1),
                digest(1),
                integer(1),
                text("rust-resolution-epoch"),
                integer(super::super::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                digest(2),
                text("crate::api::nested"),
                text("value"),
                text("item"),
                integer(1),
            ],
        ));
        queries.push(pin(
            "rust_crate_named_reexport_targets",
            super::super::rust_unit_summaries::NAMED_REEXPORT_TARGETS_SQL,
            vec![integer(1), text("crate"), text("type"), text("selected")],
        ));
        queries.push(pin(
            "rust_unit_summary_export_point",
            super::super::unit_summaries::UNIT_EXPORT_POINT_SQL,
            vec![integer(1), text("type"), integer(1)],
        ));
        queries.push(pin(
            "rust_unit_summary_dependents",
            super::super::unit_summaries::UNIT_DEPENDENTS_SQL,
            vec![
                digest(1),
                text(&"7".repeat(64)),
                text("rust"),
                integer(1),
                digest(0),
            ],
        ));
        queries.push(pin(
            "rust_unit_summary_import_graph_binding_surfaces",
            super::super::rust_unit_summaries::RUST_SUMMARY_BINDING_SURFACES_SQL,
            vec![text("[\"src/lib.rs\"]")],
        ));
        queries.push(pin(
            "rust_unit_summary_import_graph_binding_completeness",
            super::super::rust_unit_summaries::RUST_SUMMARY_BINDING_COMPLETENESS_SQL,
            vec![text("[\"src/lib.rs\"]")],
        ));
        queries.push(pin(
            "rust_unit_summary_import_graph_module_candidates",
            super::super::rust_unit_summaries::RUST_SUMMARY_MODULE_CANDIDATES_SQL,
            vec![text("[[0,1,\"crate\"]]")],
        ));
        queries.push(pin(
            "unit_summary_graph_join",
            super::super::unit_summaries::UNIT_GRAPH_JOIN_SQL,
            vec![integer(1)],
        ));
        queries.push(pin(
            "unit_summary_withdraw_replaced_blob",
            super::super::unit_summaries::WITHDRAW_VERSIONS_OF_REPLACED_BLOB_SQL,
            vec![text(OID), text("go"), Value::Blob(Vec::new())],
        ));
        queries
    }

    #[doc(hidden)]
    pub fn plan_rows(
        conn: &Connection,
        query: &PinnedQuery,
    ) -> std::result::Result<Vec<String>, String> {
        if query.name == "rust_impl_children" {
            use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

            // Match the retained resolution reader's production policy. Other
            // pins still run under their original general-reader policy.
            let previous = conn
                .db_config(SQLITE_DBCONFIG_ENABLE_QPSG)
                .map_err(|error| error.to_string())?;
            conn.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, true)
                .map_err(|error| error.to_string())?;
            let plan = plan_rows_for_sql(conn, &query.sql, &query.params);
            conn.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, previous)
                .map_err(|error| error.to_string())?;
            plan
        } else {
            plan_rows_for_sql(conn, &query.sql, &query.params)
        }
    }

    #[doc(hidden)]
    pub fn plan_rows_for_sql(
        conn: &Connection,
        sql: &str,
        params: &[Value],
    ) -> std::result::Result<Vec<String>, String> {
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .map_err(|error| format!("prepare: {error}"))?;
        statement
            .query_map(params_from_iter(params.iter()), |row| {
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests {
    #[cfg(test)]
    use super::rust_tests_test_support::*;

    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    #[cfg(test)]
    use std::collections::{HashMap, HashSet};

    #[cfg(test)]
    use std::path::PathBuf;

    #[cfg(test)]
    use rusqlite::Connection;

    #[cfg(test)]
    use super::super::AnalyzerStore;

    // The pinned SQL, its bindings, and the two helpers that plan it live in
    // `pinned_plans` so the benchmark can call them too; the pin tests in
    // `store/mod.rs` still reach them through this module's path, which is why
    // the three they use are re-exported rather than merely imported.
    #[cfg(test)]
    use super::pinned_plans::OID;

    #[cfg(test)]
    use super::pinned_plans::{pinned_queries, plan_rows};

    #[cfg(test)]
    use super::pinned_plans::RUST_MACRO_WALK_QUERIES;
    #[cfg(test)]
    pub(crate) use super::pinned_plans::prepare_pin_context;
    #[cfg(test)]
    pub(crate) use super::pinned_plans::{explain_pin, pinned};

    #[cfg(test)]
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    #[cfg(test)]
    use brokk_bifrost_core::cache_gc::planner_statistics_repairs;

    #[cfg(test)]
    use brokk_bifrost_core::cache_gc::planner_statistics_row_count;

    #[cfg(test)]
    use brokk_bifrost_core::cache_gc::with_representative_statistics;

    #[cfg(test)]
    pub(crate) fn assert_pinned_query_uses_index(
        conn: &Connection,
        state: PlannerStatisticsState,
        name: &str,
        expected_index: &str,
        forbidden_details: &[&str],
    ) {
        let plan = explain_pin(conn, &pinned(name));
        assert!(
            plan.iter().any(|detail| detail.contains(expected_index)),
            "{state} {name}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| {
                forbidden_details
                    .iter()
                    .all(|forbidden| !detail.contains(forbidden))
            }),
            "{state} {name}: {plan:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn path_symbol_candidate_blob_batch_seeks_populated_tables_at_900_arity() {
        use syn::visit::Visit;
        // Select the production statement structurally, rather than maintaining
        // a second SQL copy or changing the statement to obtain its plan.
        struct Statement {
            name: &'static str,
            sql: Option<String>,
        }
        impl<'ast> Visit<'ast> for Statement {
            fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                if item.sig.ident == self.name {
                    self.visit_block(&item.block);
                }
            }
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                if item.sig.ident == self.name {
                    self.visit_block(&item.block);
                }
            }
            fn visit_local(&mut self, local: &'ast syn::Local) {
                if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "sql") {
                    let syn::Expr::Macro(expression) = local.init.as_ref().unwrap().expr.as_ref()
                    else {
                        panic!("production path-symbol SQL must be a format literal");
                    };
                    assert!(expression.mac.path.is_ident("format"));
                    let literal: syn::LitStr = syn::parse2(expression.mac.tokens.clone()).unwrap();
                    assert!(self.sql.replace(literal.value()).is_none());
                }
                syn::visit::visit_local(self, local);
            }
        }
        let source = syn::parse_file(include_str!("mod.rs")).unwrap();
        let mut statement = Statement {
            name: "path_symbol_rows_for_blob_keys_at_snapshots",
            sql: None,
        };
        statement.visit_file(&source);
        let placeholders = std::iter::repeat_n("?", 900).collect::<Vec<_>>().join(",");
        let sql = statement
            .sql
            .expect("production path-symbol statement")
            .replace("{placeholders}", &placeholders);
        let mut imports = Statement {
            name: "blobs_with_structured_imports_conn",
            sql: None,
        };
        imports.visit_file(&source);
        let import_sql = imports
            .sql
            .expect("production import-presence statement")
            .replace("{placeholders}", &placeholders)
            .replace(
                "{PARSED_BLOB_COMPLETE_CONDITION}",
                super::super::PARSED_BLOB_COMPLETE_CONDITION,
            );
        let parameters = std::iter::once(rusqlite::types::Value::Text("javascript".into()))
            .chain(std::iter::once(rusqlite::types::Value::Blob(Vec::new())))
            .chain((1..=900).map(|id| rusqlite::types::Value::Text(format!("{id:040x}"))))
            .collect::<Vec<_>>();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .unwrap();
        // Like adjacent access-plan fixtures, populate real rows independently
        // of publication FKs. Every bound OID below names a populated blob.
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            WITH RECURSIVE ids(id) AS (VALUES(1) UNION ALL SELECT id+1 FROM ids WHERE id<4096)
            INSERT INTO blobs(id,blob_oid,lang,generation) SELECT id,printf('%040x',id),'javascript',0 FROM ids;
            INSERT INTO blob_meta(blob_id,lang,contains_tests,content_package,stored_unit_count,range_count,signature_count,signature_metadata_count,supertype_count,child_count,import_statement_count,type_identifier_count,is_complete)
            SELECT id,'javascript',0,'',0,0,0,0,0,0,0,0,1 FROM blobs;
            INSERT INTO import_statements(blob_id,lang,ordinal,statement)
            SELECT id,'javascript',0,'import value from module' FROM blobs;
            UPDATE blob_meta SET import_statement_count=1;
            INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from)
            SELECT id,printf('%064d',0),'javascript',0,printf('src/module%d.js',id),blob_oid,printf('%064d',0),1 FROM blobs;
            INSERT INTO workspace_file_path_symbol_rows(file_version_id,kind,package_name,short_name,exact_fqn,normalized_fqn,requires_imports)
            SELECT id,3,'',printf('module%d.js',id),printf('src/module%d.js',id),printf('src/module%d.js',id),1 FROM blobs;
            INSERT INTO temp.selected_workspace_revisions VALUES(printf('%064d',0),'javascript',0,1);").unwrap();
        let mut plans = Vec::new();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = super::pinned_plans::plan_rows_for_sql(&conn, &sql, &parameters).unwrap();
            eprintln!("path-symbol candidate batch {state}: {plan:#?}");
            let count = conn
                .prepare(&sql)
                .unwrap()
                .query_map(rusqlite::params_from_iter(parameters.iter()), |_| Ok(()))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .len();
            assert_eq!(count, 900, "the bound production-arity probe must execute");
            // The import-presence batch the set build issues beside it must
            // seek by the same bound OIDs.
            let import_plan =
                super::pinned_plans::plan_rows_for_sql(&conn, &import_sql, &parameters).unwrap();
            eprintln!("import-presence batch {state}: {import_plan:#?}");
            let import_count = conn
                .prepare(&import_sql)
                .unwrap()
                .query_map(rusqlite::params_from_iter(parameters.iter()), |_| Ok(()))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .len();
            assert_eq!(import_count, 900, "the import probe must execute real OIDs");
            plans.push((state, plan, import_plan));
        }
        for (state, plan, import_plan) in plans {
            assert!(
                plan.iter()
                    .any(|line| line.starts_with("SEARCH candidates USING")
                        && line.contains("blob_oid=? AND lang=? AND parse_variant=?")),
                "{state}: candidate lookup must seek the bound OIDs: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .any(|line| line.starts_with("SEARCH blobs USING")
                        && (line.contains("blob_oid=?")
                            || line.contains("INTEGER PRIMARY KEY (rowid=?)"))),
                "{state}: blob lookup must use its index: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .any(|line| (line.starts_with("SEARCH versions USING")
                        || line.starts_with("SEARCH files USING"))
                        && line.contains("blob_oid=?")),
                "{state}: selected files must seek the bound blob identities: {plan:#?}"
            );
            assert!(
                !plan.iter().any(|line| line.starts_with("SCAN rows")
                    || line.starts_with("SCAN files")
                    || line.starts_with("SCAN versions")
                    || line.contains("SCAN workspace_file_path_symbol_rows")
                    || line.contains("SCAN workspace_file_versions")),
                "{state}: path-symbol and file tables must not scan: {plan:#?}"
            );
            assert!(
                import_plan
                    .iter()
                    .any(|line| line.starts_with("SEARCH") && line.contains("blob_oid=?")),
                "{state}: import presence must seek the bound OIDs: {import_plan:#?}"
            );
            assert!(
                !import_plan.iter().any(|line| line.starts_with("SCAN")),
                "{state}: import presence must not scan: {import_plan:#?}"
            );
        }
    }

    #[cfg(test)]
    fn fill_reverse_candidate_fixture(conn: &Connection) {
        // Like the neighboring access-plan fixtures, populate source rows
        // without publishing fragments: this pin tests indexed reads.
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        for blob in 1..=16 {
            for key in 1..=256_i64 {
                conn.execute(
                    "INSERT INTO resolution_sites(blob_id,site,role,namespace) VALUES(?1,?2,0,0)",
                    rusqlite::params![blob, key],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO resolution_semantic_sites(blob_id,source_site,namespace,semantic_role,semantic_key) VALUES(?1,?2,'value','reference',?3)",
                    rusqlite::params![blob, key, key + 1000],
                ).unwrap();
                conn.execute(
                    "INSERT INTO resolution_reference_lookup_identities(blob_id,semantic_key,identity_id) VALUES(?1,?2,?3)",
                    rusqlite::params![blob, key + 1000, key],
                ).unwrap();
                conn.execute(
                    "INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_identity,end_lead_scoped,body)
                     VALUES(?1,?2,?3,0,12,?3,0,jsonb('[[],null,[],null,[],null,[],null,[],[],[]]'))",
                    rusqlite::params![blob, key * 2, key],
                ).unwrap();
                if blob == 1 {
                    conn.execute(
                        "INSERT INTO resolution_identities(id,identity_digest,semantic_language,namespace,spelling) VALUES(?1,?2,0,0,?3)",
                        rusqlite::params![key, [key.to_le_bytes().as_slice(), &[0; 24]].concat(), format!("name{key}")],
                    ).unwrap();
                }
                conn.execute(
                    "INSERT INTO python_member_operations(blob_id,site,name_site,form,effect,name_kind) VALUES(?1,?2,?2,0,0,?3)",
                    rusqlite::params![blob, key, key % 3],
                ).unwrap();
                let operation = conn.last_insert_rowid();
                if key % 3 != 2 {
                    conn.execute(
                        "INSERT INTO python_member_operation_names VALUES(?1,0,?2)",
                        rusqlite::params![
                            operation,
                            if key % 3 == 0 {
                                format!("name{key}")
                            } else {
                                "name".into()
                            }
                        ],
                    )
                    .unwrap();
                }
                let fixed = format!("[0,0,0,-{key}]");
                let body = format!("[[],null,[],null,{fixed},null,[],null,[],[],[]]");
                conn.execute(
                    "INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_scoped,root_terminal,body,end_fixed_key,end_open_tail)
                     VALUES(?1,?2,?3,0,-1,0,?3,jsonb(?4),?5,0)",
                    rusqlite::params![blob, key * 2 + 1, key, body, fixed],
                ).unwrap();
                conn.execute(
                    "INSERT INTO resolution_root_route_segments(blob_id,path_key,position,terminal_spelling,reference_source_site,reference_start_byte,reference_end_byte)
                     VALUES(?1,?2,1,'name',?3,0,1)",
                    rusqlite::params![blob, key * 2 + 1, key],
                ).unwrap();
                conn.execute(
                    "INSERT INTO resolution_qualified_routes(blob_id,reference,precedence_ordinal,qualifier_slot,lookup,source_lookup,namespace,projection_output_slot,projection_kind,coarse_gap_reason)
                     VALUES(?1,?2,0,?2,?2,?2,0,?2,0,0)",
                    rusqlite::params![blob, key],
                ).unwrap();
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn reverse_candidate_union_seeks_all_arms_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            prepare_pin_context(&conn);
            fill_reverse_candidate_fixture(&conn);
            state.install(&conn);
            for (width, lexical) in [1, 64, 256, 4096]
                .into_iter()
                .flat_map(|width| [(width, true), (width, false)])
            {
                conn.execute(
                    super::super::resolution_operation::REVERSE_CANDIDATE_KEYS_CLEAR_SQL,
                    [],
                )
                .unwrap();
                let requested = (0..width)
                    .map(|ordinal| {
                        (
                            ordinal,
                            ordinal,
                            ordinal % 16 + 1,
                            ordinal / 16 + 1,
                            1,
                            1,
                            lexical,
                        )
                    })
                    .collect::<Vec<_>>();
                conn.execute(
                    super::super::resolution_operation::REVERSE_CANDIDATE_KEYS_INSERT_SQL,
                    [serde_json::to_string(&requested).unwrap()],
                )
                .unwrap();
                for pin_name in [
                    "reverse_candidates",
                    "reverse_candidates_with_lookup_inventory",
                    "python_reverse_candidates",
                ] {
                    let plan = explain_pin(&conn, &pinned(pin_name));
                    // The three UNION arms may scan their driving TEMP key table,
                    // but every base-table read must be a constrained indexed SEARCH.
                    for (arm, index, constraints) in [
                        (
                            "lookup",
                            "resolution_paths_end_lookup_identity",
                            "blob_id=? AND end_lead_identity=?",
                        ),
                        (
                            "prefixed root",
                            "resolution_paths_root_terminal",
                            "blob_id=? AND root_terminal=?",
                        ),
                        (
                            "qualified route",
                            "resolution_qualified_routes_source_lookup",
                            "blob_id=? AND source_lookup=?",
                        ),
                    ] {
                        assert!(
                            plan.iter().any(|detail| detail.starts_with("SEARCH ")
                                && detail.contains(index)
                                && detail.contains(constraints)),
                            "{state}, {width} keys, {arm} must seek its indexed base-table key: {plan:#?}"
                        );
                    }
                    assert_eq!(
                        plan.iter()
                            .filter(|detail| detail.starts_with("SEARCH s USING PRIMARY KEY")
                                && detail.contains("blob_id=? AND site=?"))
                            .count(),
                        match pin_name {
                            "reverse_candidates" => 3,
                            "python_reverse_candidates" => 5,
                            _ => 4,
                        },
                        "{state}, {width} keys, {pin_name}: each arm must seek its site: {plan:#?}"
                    );
                    if pin_name != "reverse_candidates" {
                        for constraint in [
                            "resolution_reference_lookup_identities_identity (identity_id=? AND blob_id=?)",
                            "sqlite_autoindex_resolution_semantic_sites_2 (blob_id=? AND semantic_role=? AND semantic_key=?)",
                        ] {
                            assert!(
                                plan.iter().any(|detail| detail.starts_with("SEARCH ")
                                    && detail.contains(constraint)),
                                "{state}, {width} keys, {pin_name}: inventory arm must seek {constraint}: {plan:#?}"
                            );
                        }
                        let count: usize = conn
                            .prepare(&pinned(pin_name).sql)
                            .unwrap()
                            .query_map([], |_| Ok(()))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap()
                            .len();
                        // Each blob has 86 prefix observations. Any-name observations
                        // do not nominate targets.
                        // An exact name additionally matches when its written
                        // fixture key is divisible by three.
                        let operation_count = if pin_name == "python_reverse_candidates" && lexical
                        {
                            width * 86
                                + (0..width)
                                    .filter(|ordinal| (ordinal / 16 + 1) % 3 == 0)
                                    .count()
                        } else {
                            0
                        };
                        assert_eq!(
                            count,
                            operation_count
                                + width
                                    * if pin_name == "python_reverse_candidates" {
                                        if lexical { 5 } else { 3 }
                                    } else if lexical {
                                        4
                                    } else {
                                        2
                                    },
                            "{state}, {width} keys: the extra arm projects semantic keys back to source sites"
                        );
                    }
                    assert!(
                        plan.iter()
                            .all(|detail| !detail.starts_with("SCAN ") || detail == "SCAN k")
                            && plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                        "{state}, {width} keys: only the driving TEMP request keys may be scanned; no base table may be scanned: {plan:#?}"
                    );
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3769: Rust field-only usage scans evaluated unrelated full resolution facts")]
    fn issue_3769_field_exclusion_seeks_exact_source_and_gap_rows() {
        use rusqlite::{StatementStatus, params, params_from_iter};

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        prepare_pin_context(&conn);
        let pin = pinned("rust_reverse_trusted_field_reference");
        conn.execute(
            "INSERT INTO temp.selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) VALUES(0,1,'rust','src/lib.rs')",
            [],
        ).unwrap();
        // Real bound source coordinates amid unrelated blobs and sites. The
        // occurrence arena is read by position, never through json_each.
        for blob in 1..=16 {
            if blob != 1 {
                conn.execute(
                    "INSERT INTO temp.selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) VALUES(?1,?1,'rust',?2)",
                    params![blob, format!("src/decoy_{blob}.rs")],
                ).unwrap();
            }
            conn.execute(
                "INSERT INTO source_occurrence_arenas VALUES(?1,jsonb('[[0,1,1,1,0]]'))",
                [blob],
            )
            .unwrap();
            for site in 0..128 {
                conn.execute(
                    "INSERT INTO resolution_sites(blob_id,site,role,namespace,site_kind,start_byte,end_byte,unqualified) VALUES(?1,?2,0,?3,?4,0,1,0)",
                    params![blob, site, pin.params[2], pin.params[3]],
                ).unwrap();
                conn.execute(
                    "INSERT INTO resolution_rust_reference_contexts VALUES(?1,?2,?2,0,0,NULL,jsonb('[]'))",
                    params![blob, site],
                ).unwrap();
                conn.execute(
                    "INSERT INTO resolution_gap_reasons VALUES(?1,?2,?2,?3)",
                    params![blob, site, pin.params[4]],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO resolution_gaps VALUES(?1,4,?2,0,?2,?2)",
                    params![blob, site],
                )
                .unwrap();
            }
        }
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            assert!(
                plan.iter().any(|row| row.contains("SEARCH mount USING")
                    && row.contains("storage_language=? AND persisted_relative_path=?")),
                "{state:?}: {plan:?}"
            );
            for table in ["site", "context", "arena", "gap", "reason"] {
                assert!(
                    plan.iter()
                        .any(|row| row.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
                    "{state:?} {table}: {plan:?}"
                );
            }
            assert!(
                !plan.iter().any(|row| row.contains("AUTOMATIC")
                    || row.contains("VIRTUAL TABLE")
                    || row.contains("TEMP B-TREE")
                    || row.contains("CO-ROUTINE")),
                "{state:?}: {plan:?}"
            );
            let mut statement = conn.prepare(&pin.sql).unwrap();
            assert!(
                statement
                    .query_row(params_from_iter(&pin.params), |row| {
                        Ok(row.get::<_, bool>(0)? && row.get::<_, bool>(1)?)
                    })
                    .unwrap()
            );
            assert_eq!(
                statement.get_status(StatementStatus::FullscanStep),
                0,
                "{state:?}: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("4c088c8231d7: selective reference-gap reads scanned unrelated persisted gaps")]
    fn reference_gap_completion_seeks_requested_subjects_with_unrelated_blob_gaps() {
        use crate::analyzer::resolution::LoweringGapOrigin;
        use crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code;
        use rusqlite::StatementStatus;
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            // This is a populated access-plan fixture, not a publication fixture.
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .unwrap();
            prepare_pin_context(&conn);
            let qualified = gap_origin_code(LoweringGapOrigin::QualifiedReference);
            conn.execute(
                "INSERT INTO temp.selected_resolution_mounts(mount_ordinal,blob_id) VALUES(0,1)",
                [],
            )
            .unwrap();
            conn.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,0,zeroblob(32),zeroblob(32))", []).unwrap();
            for key in 0..=256_i64 {
                conn.execute("INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES(1,?1,0,?2)", rusqlite::params![10000+key,if [2,3].contains(&key) {qualified} else {0}]).unwrap();
                conn.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES(1,?1,?2,0,?3,?3)",rusqlite::params![if key==0 {0}else{4},key,10000+key]).unwrap();
            }
            conn.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key) VALUES(1,10001)", []).unwrap();
            conn.execute("INSERT INTO temp.selected_resolution_stage_qualified_routes(host_ordinal,producer_id,sequence,reference_key,qualifier_slot_key,lookup_key,source_lookup_key,projection_output_slot_key,coarse_gap_reason_key,precedence_ordinal,namespace,projection_kind) VALUES(0,1,0,2,2,2,2,2,10002,0,0,0)", []).unwrap();
            conn.execute("INSERT INTO resolution_qualified_routes(blob_id,reference,precedence_ordinal,qualifier_slot,lookup,source_lookup,namespace,projection_output_slot,projection_kind,coarse_gap_reason) VALUES(1,3,0,3,1,1,0,3,0,10003)", []).unwrap();
            let mut baseline = std::collections::BTreeMap::new();
            for noise in [0_i64, 1024, 8192] {
                conn.execute(
                    "DELETE FROM resolution_gaps WHERE blob_id=1 AND subject>=100000",
                    [],
                )
                .unwrap();
                for key in 0..noise {
                    conn.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES(1,4,?1,0,?1,10000)",[100000+key]).unwrap();
                }
                state.install(&conn);
                for arity in [0, 1, 64, 256] {
                    let pin = pinned(&format!("selected_reference_gap_completions_{arity}"));
                    for hit in [false, true] {
                        let keys = if hit {
                            (1..=arity).collect::<Vec<_>>()
                        } else {
                            (50000..50000 + arity).collect::<Vec<_>>()
                        };
                        let keys = serde_json::to_string(&keys).unwrap();
                        let bindings = rusqlite::named_params! {":host":0,":mount_base":0,":blob":1,":keys":keys,":qualified_origin":qualified,":local_base":0};
                        let plan = conn
                            .prepare(&format!("EXPLAIN QUERY PLAN {}", pin.sql))
                            .unwrap()
                            .query_map(bindings, |row| row.get::<_, String>(3))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let mut statement = conn.prepare(&pin.sql).unwrap();
                        let actual = statement
                            .query_map(bindings, |row| {
                                Ok((
                                    row.get::<_, i64>(0)?,
                                    row.get::<_, i64>(1)?,
                                    row.get::<_, i64>(2)?,
                                ))
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let expected = std::iter::once((0, 0, 10000))
                            .chain(
                                (4..=arity)
                                    .filter(|_| hit)
                                    .map(|key| (4, i64::from(key), 10000 + i64::from(key))),
                            )
                            .collect::<Vec<_>>();
                        assert_eq!(
                            actual, expected,
                            "{state:?} arity={arity} hit={hit} noise={noise}"
                        );
                        let steps = statement.get_status(StatementStatus::VmStep);
                        let first = *baseline.entry((arity, hit)).or_insert(steps);
                        eprintln!(
                            "reference gaps {state:?} arity={arity} hit={hit} noise={noise} vm={steps} plan={plan:?}"
                        );
                        assert!(
                            steps <= first + first / 4 + 128,
                            "unrelated gaps changed work: {state:?} arity={arity} hit={hit} noise={noise} first={first} steps={steps} plan={plan:?}"
                        );
                        assert!(
                            plan.iter()
                                .filter(|p| p.contains("SEARCH fact")
                                    && p.contains("blob_id=? AND covers=? AND subject=?"))
                                .count()
                                >= 2,
                            "{state:?}: {plan:?}"
                        );
                    }
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn external_member_owner_inverse_seeks_the_member_primary_key() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            state.install(&conn);
            let owner_plan = explain_pin(&conn, &pinned("intrinsic_member_owner_indexed"));
            assert!(
                owner_plan.iter().any(|detail| detail.contains(
                    "SEARCH jvm_external_owners USING PRIMARY KEY (provider_id=? AND owner_fqn=?)"
                )),
                "{state}: {owner_plan:?}"
            );
            assert!(
                owner_plan
                    .iter()
                    .all(|detail| !detail.contains("SCAN jvm_external_owners")),
                "{state}: {owner_plan:?}"
            );
            let plan = explain_pin(&conn, &pinned("external_member_owner_by_definition"));
            assert!(
                plan.iter().any(|detail| detail.contains(
                    "SEARCH member USING PRIMARY KEY (provider_id=? AND owner_fqn=? AND ordinal=?)"
                )),
                "{state}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("SCAN member")
                        && !detail.contains("SCAN inventory")),
                "{state}: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn ordinary_unsupported_reason_access_compares_ordered_seeks() {
        use crate::analyzer::store::resolution_prepare::authority_rows;
        use rusqlite::StatementStatus;
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            for size in [16, 256, 1024] {
                conn.execute("DELETE FROM resolution_gap_reasons", [])
                    .unwrap();
                for key in 0..size {
                    for origin in [0, 1] {
                        conn.execute("INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES(1,?1,?2,?3)",rusqlite::params![key*2+origin,key,origin]).unwrap();
                    }
                }
                state.install(&conn);
                for (name, sql) in [
                    (
                        "in",
                        "SELECT reason FROM resolution_gap_reasons WHERE blob_id=?1 AND site=?2 AND origin IN (?3,?4,?5) ORDER BY reason",
                    ),
                    ("ordered_union", authority_rows::UNSUPPORTED_GAP_REASONS_SQL),
                ] {
                    for key in [size - 1, size] {
                        let plan = conn
                            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                            .unwrap()
                            .query_map([1, key, 0, 1, 2], |row| row.get::<_, String>(3))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let mut statement = conn.prepare(sql).unwrap();
                        let rows = statement
                            .query_map([1, key, 0, 1, 2], |row| row.get::<_, i64>(0))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let vm = statement.get_status(StatementStatus::VmStep);
                        assert_eq!(
                            rows,
                            if key < size {
                                vec![key * 2, key * 2 + 1]
                            } else {
                                vec![]
                            }
                        );
                        eprintln!(
                            "B1 unsupported state={state} shape={name} size={size} key={key} rows={rows:?} vm={vm} plan={plan:?}"
                        );
                        if name == "ordered_union" {
                            assert!(vm < 100, "ordered origin seeks remain bounded: {vm}");
                        }
                    }
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn ordinary_lookup_access_is_bounded_by_requested_keys() {
        use crate::analyzer::store::resolution_prepare::authority_rows;
        use rusqlite::StatementStatus;
        let mut failures = Vec::new();
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO resolution_sites(blob_id,site,role,namespace) VALUES(1,0,0,0); INSERT INTO resolution_node_catalog(blob_id,local_key,identity_digest,source_scope) VALUES(1,10,zeroblob(32),0)").unwrap();
            let mut observed = std::collections::BTreeMap::<(&str, bool), Vec<i32>>::new();
            for size in [16, 256, 1024] {
                conn.execute("DELETE FROM resolution_paths", []).unwrap();
                for key in 1..=size {
                    for shared in [false, true] {
                        conn.execute("INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_local,end_lead_identity,end_lead_scoped,body) VALUES(1,?1,0,0,12,?2,?3,0,jsonb('[[],null,[],null,[],null,[],null,[],[],[]]'))",rusqlite::params![key*2+i64::from(shared),(!shared).then_some(key),shared.then_some(key)]).unwrap();
                    }
                    conn.execute("INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_scoped,body) VALUES(1,?1,?2,0,?3,0,jsonb('[[],null,[],null,[],null,[],null,[],[],[]]'))",rusqlite::params![10000+key,20000+key,30000+key]).unwrap();
                }
                for (path, start, end) in [(50000, 11, 10), (50001, 12, 11)] {
                    conn.execute("INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_scoped,body) VALUES(1,?1,?2,0,?3,0,jsonb('[[],null,[],null,[],null,[],null,[],[],[]]'))",rusqlite::params![path,start,end]).unwrap();
                }
                state.install(&conn);
                for (name, sql, scope) in [
                    ("local", authority_rows::LOOKUP_REFERENCE_LOCAL_SQL, None),
                    ("shared", authority_rows::LOOKUP_REFERENCE_SHARED_SQL, None),
                    (
                        "scoped_local",
                        authority_rows::SCOPED_LOOKUP_REFERENCE_LOCAL_SQL,
                        Some(0),
                    ),
                    (
                        "scoped_shared",
                        authority_rows::SCOPED_LOOKUP_REFERENCE_SHARED_SQL,
                        Some(0),
                    ),
                ] {
                    for key in [size, size + 1] {
                        let plan = conn
                            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                            .unwrap()
                            .query_map(rusqlite::params![1, key, scope], |row| {
                                row.get::<_, String>(3)
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let mut statement = conn.prepare(sql).unwrap();
                        let rows = statement
                            .query_map(rusqlite::params![1, key, scope], |row| row.get::<_, i64>(0))
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let vm = statement.get_status(StatementStatus::VmStep);
                        assert_eq!(rows, if key <= size { vec![0] } else { vec![] });
                        observed.entry((name, key <= size)).or_default().push(vm);
                        eprintln!(
                            "B1 lookup state={state} kind={name} size={size} hit={} rows={rows:?} vm={vm} plan={plan:?}",
                            key <= size
                        );
                    }
                }
            }
            for (key, steps) in observed {
                if steps.iter().max().unwrap() - steps.iter().min().unwrap() > 64 {
                    failures.push(format!("state={state} {key:?} {steps:?}"));
                }
            }
        }
        eprintln!("B1 lookup unbounded work: {failures:?}");
        assert!(
            failures.is_empty(),
            "existing lookup and reverse indexes must bound the final shape: {failures:?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn ordinary_root_terminal_access_is_keyed_amid_unrelated_terminals() {
        use crate::analyzer::store::resolution_prepare::authority_rows;
        use rusqlite::StatementStatus;
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO resolution_sites(blob_id,site,role,namespace) VALUES(1,0,0,0)").unwrap();
            for size in [16, 256, 1024] {
                conn.execute("DELETE FROM resolution_paths", []).unwrap();
                for key in 1..=size {
                    for shared in [false, true] {
                        let terminal = if shared { -key } else { key };
                        let body =
                            format!("[[],null,[],null,[0,0,{terminal}],null,[],null,[],[],[]]");
                        let fixed = format!("[0,0,{terminal}]");
                        conn.execute("INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_local,end_lead_scoped,root_terminal,body,end_fixed_key,end_open_tail) VALUES(1,?1,0,0,-1,0,0,?2,jsonb(?3),?4,0)", rusqlite::params![key*2+i64::from(shared), shared.then_some(key), body, fixed]).unwrap();
                    }
                }
                state.install(&conn);
                for (name, sql) in [
                    ("local", authority_rows::ROOT_DEMAND_LOCAL_SQL),
                    ("shared", authority_rows::ROOT_DEMAND_SHARED_SQL),
                ] {
                    for forced in [false, true] {
                        let index = if name == "local" {
                            "resolution_paths_root_local_terminal"
                        } else {
                            "resolution_paths_root_terminal"
                        };
                        let sql = if forced {
                            sql.replace(
                                "FROM resolution_paths p JOIN",
                                &format!("FROM resolution_paths p INDEXED BY {index} JOIN"),
                            )
                        } else {
                            sql.to_owned()
                        };
                        for key in [size, size + 1] {
                            let plan = conn
                                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                                .unwrap()
                                .query_map([1, key], |row| row.get::<_, String>(3))
                                .unwrap()
                                .collect::<rusqlite::Result<Vec<_>>>()
                                .unwrap();
                            let mut statement = conn.prepare(&sql).unwrap();
                            let rows = statement
                                .query_map([1, key], |row| {
                                    Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))
                                })
                                .unwrap()
                                .collect::<rusqlite::Result<Vec<_>>>()
                                .unwrap();
                            let vm = statement.get_status(StatementStatus::VmStep);
                            assert_eq!(
                                rows,
                                if key <= size {
                                    vec![(0, false)]
                                } else {
                                    vec![]
                                }
                            );
                            eprintln!(
                                "B1 root terminal state={state} kind={name} forced={forced} size={size} key={key} rows={rows:?} vm={vm} plan={plan:?}"
                            );
                            if forced {
                                assert!(
                                    vm < 200,
                                    "terminal seek must not scale with unrelated paths: {vm}"
                                );
                            }
                        }
                    }
                }
                let bytes = conn.prepare("SELECT name,sum(pgsize),sum(payload) FROM dbstat WHERE name IN ('resolution_paths_root_terminal','resolution_paths_root_local_terminal','resolution_sites_reference_range') GROUP BY name ORDER BY name").unwrap().query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                eprintln!("B1 root/index bytes state={state} size={size}: {bytes:?}");
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn ordinary_reference_range_access_compares_covering_and_forced_seeks() {
        use crate::analyzer::store::resolution_prepare::authority_rows;
        use rusqlite::StatementStatus;
        for state in PlannerStatisticsState::BOTH {
            for covering in [false, true] {
                let store = AnalyzerStore::open_ephemeral().unwrap();
                let conn = store.conn.lock().unwrap();
                conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
                conn.execute_batch("DROP INDEX resolution_sites_reference_range")
                    .unwrap();
                conn.execute_batch(if covering {
                    "CREATE INDEX resolution_sites_reference_range ON resolution_sites(blob_id,start_byte,end_byte,role,site,namespace)"
                } else {
                    "CREATE INDEX resolution_sites_reference_range ON resolution_sites(blob_id,start_byte,end_byte,role,site)"
                }).unwrap();
                for size in [16, 256, 1024] {
                    conn.execute("DELETE FROM resolution_sites", []).unwrap();
                    for key in 0..size {
                        conn.execute("INSERT INTO resolution_sites(blob_id,site,role,namespace,site_kind,start_byte,end_byte,unqualified) VALUES(1,?1,0,0,0,?1,?1+1,1)", [key]).unwrap();
                    }
                    state.install(&conn);
                    for forced in [false, true] {
                        let sql = if forced {
                            authority_rows::SEMANTIC_SITES_2_SQL.replace("FROM resolution_sites WHERE", "FROM resolution_sites INDEXED BY resolution_sites_reference_range WHERE")
                        } else {
                            authority_rows::SEMANTIC_SITES_2_SQL.to_owned()
                        };
                        for key in [size - 1, size + 1] {
                            let parameters = [1, key, key + 1, 0];
                            let plan = conn
                                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                                .unwrap()
                                .query_map(parameters, |row| row.get::<_, String>(3))
                                .unwrap()
                                .collect::<rusqlite::Result<Vec<_>>>()
                                .unwrap();
                            let mut statement = conn.prepare(&sql).unwrap();
                            let rows = statement
                                .query_map(parameters, |row| {
                                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                                })
                                .unwrap()
                                .collect::<rusqlite::Result<Vec<_>>>()
                                .unwrap();
                            let steps = statement.get_status(StatementStatus::VmStep);
                            assert_eq!(rows.len(), usize::from(key < size));
                            eprintln!(
                                "B1 range access state={state} covering={covering} forced={forced} size={size} key={key} rows={rows:?} vm={steps} plan={plan:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn ordinary_authority_queries_bind_and_seek_in_both_statistics_states() {
        use crate::analyzer::store::resolution_prepare::{
            authority_rows, rust_authority, typed_rows,
        };

        use rusqlite::types::Value;
        let mut failures = Vec::new();
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open planner store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .unwrap();
            prepare_pin_context(&conn);
            state.install(&conn);
            let mut queries = authority_rows::PINNED_SQL
                .iter()
                .map(|(name, sql)| ((*name).to_owned(), (*sql).to_owned()))
                .collect::<Vec<_>>();
            queries.extend([
                (
                    "rust_reference_contexts".into(),
                    rust_authority::REFERENCES_SQL.into(),
                ),
                (
                    "rust_declaration_authorities".into(),
                    rust_authority::DECLARATIONS_SQL.into(),
                ),
                (
                    "typed_frontier_completion".into(),
                    typed_rows::frontier_completion_sql(),
                ),
                (
                    "typed_gap_reason_provenance".into(),
                    typed_rows::GAP_REASON_PROVENANCE_SQL.into(),
                ),
            ]);
            for (name, sql) in queries {
                let mut statement = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
                let mut parameters = vec![Value::Integer(0); statement.parameter_count()];
                for index in 1..=parameters.len() {
                    if sql.contains(&format!("json_each(?{index})")) {
                        parameters[index - 1] =
                            Value::Text(if index == 1 { "[[0,0]]" } else { "[0]" }.into());
                    }
                }
                if sql.contains("?3 IS NULL") {
                    parameters[2] = Value::Null;
                }
                if sql.contains("identity_digest=?2") {
                    parameters[1] = Value::Blob(vec![0; 32]);
                }
                let plan = statement
                    .query_map(rusqlite::params_from_iter(parameters), |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                eprintln!("B1 plan {state} {name}: {plan:?}");
                if plan.iter().any(|row| row.contains("SCAN resolution_")) {
                    failures.push(format!("{state} {name}: {plan:?}"));
                }
                let required = match name.as_str() {
                    "semantic_sites_2_sql" => Some("resolution_sites_reference_range"),
                    "semantic_sites_3_sql" => Some("source_declarations_name_range"),
                    "unsupported_gap_reasons_sql" => Some("resolution_gap_reasons_site"),
                    "qualified_route_reference_sites_sql" => {
                        Some("resolution_qualified_routes_source_lookup")
                    }
                    "root_demand_local_sql" => Some("resolution_paths_root_local_terminal"),
                    "root_demand_shared_sql" => Some("resolution_paths_root_terminal"),
                    "lookup_reference_local_sql" | "scoped_lookup_reference_local_sql" => {
                        Some("resolution_paths_end_lookup_local")
                    }
                    "lookup_reference_shared_sql" | "scoped_lookup_reference_shared_sql" => {
                        Some("resolution_paths_end_lookup_identity")
                    }
                    _ => None,
                };
                if let Some(required) = required
                    && !plan.iter().any(|row| row.contains(required))
                {
                    failures.push(format!("{state} {name} must use {required}: {plan:?}"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "authority plan failures: {failures:#?}"
        );
    }

    #[cfg(test)]
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
        // Optional operator-supplied statements use concrete values from this
        // store. They cover readers outside the pinned registry in a schema
        // comparison without adding one-off production query registrations.
        if let Some(path) = std::env::var_os("BIFROST_3016_EXTRA_QUERIES") {
            let queries: Vec<(String, String, Vec<serde_json::Value>)> = serde_json::from_reader(
                std::fs::File::open(&path).unwrap_or_else(|error| {
                    panic!("open extra operator queries {path:?}: {error}")
                }),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "extra queries in {path:?} are JSON [name, SQL, parameters] triples: {error}"
                )
            });
            for (name, sql, parameters) in queries {
                let parameters = parameters
                    .into_iter()
                    .map(|value| match value {
                        serde_json::Value::Null => rusqlite::types::Value::Null,
                        serde_json::Value::String(value) => rusqlite::types::Value::Text(value),
                        serde_json::Value::Number(number) => {
                            rusqlite::types::Value::Integer(number.as_i64().unwrap_or_else(|| {
                                panic!("operator query {name}: parameter {number} is not an i64")
                            }))
                        }
                        value => panic!("operator query {name}: unsupported parameter {value:?}"),
                    })
                    .collect::<Vec<_>>();
                let record = match super::pinned_plans::plan_rows_for_sql(&conn, &sql, &parameters)
                {
                    Ok(plan) => serde_json::json!({"pin": name, "plan": plan}),
                    Err(error) => serde_json::json!({"pin": name, "error": error}),
                };
                println!("{record}");
            }
        }
    }

    #[cfg(test)]
    /// Batch typed-fact readers and scalar ownership readers must seek
    /// stored resolution tables under both statistics states. Array readers
    /// may scan json_each or its subquery; no reader may scan a resolution
    /// table once per request.
    #[test]
    fn every_typed_fact_read_is_driven_by_its_key_array() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let names = super::pinned_plans::TYPED_FACT_PINS
                .iter()
                .map(|(name, _)| *name)
                .chain(
                    super::pinned_plans::TYPED_OWNER_PINS
                        .iter()
                        .map(|(name, _, _)| *name),
                )
                .chain([
                    "resolution_qualified_routes_by_slot_lookup",
                    "resolution_qualified_routes_inventory",
                ]);
            for name in names {
                let plan = explain_pin(&conn, &pinned(name));
                if name == "resolution_jvm_aliases_by_definition" {
                    assert!(
                        plan.iter()
                            .any(|row| row.contains("resolution_jvm_aliases_declaration_site")),
                        "{state} {name}: {plan:?}"
                    );
                    assert!(
                        plan.iter().all(|row| !row.starts_with("SCAN alias")
                            && !row.starts_with("SCAN definition")
                            && !row.contains("AUTOMATIC")),
                        "{state} {name}: {plan:?}"
                    );
                }
                let scanned = plan
                    .iter()
                    .filter(|row| row.contains("SCAN resolution_"))
                    .collect::<Vec<_>>();
                assert!(
                    scanned.is_empty(),
                    "{state} {name} must seek every resolution table it opens, not scan it: \
                     scans {scanned:?}, whole plan {plan:?}"
                );
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn rust_reason_owners_seek_declaration_site_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            assert_pinned_query_uses_index(
                &conn,
                state,
                "resolution_rust_reason_owners",
                "resolution_rust_declaration_authorities_source_site",
                &[
                    "SCAN resolution_rust_declaration_authorities",
                    "AUTOMATIC",
                    "TEMP B-TREE",
                ],
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn rust_receiver_impl_targets_seek_subject_and_trait_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("rust_receiver_impl_targets"));
            eprintln!("Rust receiver impl Targets {state}: {plan:?}");
            for required in [
                "SEARCH owner_mount USING PRIMARY KEY (mount_ordinal=?)",
                "resolution_unit_summary_members_blob (blob_id=?)",
                "rust_resolution_unit_summary_exports_declaration (summary_id=? AND declaration_member_ordinal=? AND declaration_site=? AND namespace=?)",
                "rust_resolution_unit_summary_trait_endpoints_target (target_unit_key=? AND target_module_path=? AND target_identity_id=?)",
                "SEARCH trait USING PRIMARY KEY (summary_id=? AND member_ordinal=? AND owner_module_path=? AND source_relation_key=? AND endpoint_role=?)",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(required)),
                    "{state} Rust receiver impl lookup must {required}: {plan:?}"
                );
            }
            assert!(
                plan.iter()
                    .all(|row| !row.starts_with("SCAN ") && !row.contains("AUTOMATIC")),
                "{state} Rust receiver impl lookup must not scan tables or build automatic indexes: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn rust_receiver_kind_seeks_each_declaration_key_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("rust_receiver_kind"));
            for required in [
                "SEARCH mount USING PRIMARY KEY (mount_ordinal=?)",
                "SEARCH semantic USING INDEX sqlite_autoindex_resolution_semantic_sites_2 (blob_id=? AND semantic_role=? AND semantic_key=?)",
                "SEARCH native USING PRIMARY KEY (blob_id=? AND source_site=?)",
                "SEARCH property USING PRIMARY KEY (blob_id=? AND declaration_id=?)",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(required)),
                    "{state} Rust receiver-kind lookup must {required}: {plan:?}"
                );
            }
            assert!(
                plan.iter().all(|row| !row.starts_with("SCAN ")),
                "{state} Rust receiver-kind lookup must not scan tables: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    /// Milestone 6's checkpoint reads rows by key, in both statistics states.
    ///
    /// The three statements the checkpoint adds each pass the keys the caller
    /// already holds as one JSON array. What has to hold is that the array is
    /// the outer loop and the table is sought: a plan that scanned
    /// `resolution_paths` or `resolution_identities` once per call would be
    /// the whole port's cost, not its saving. Lane LD measured the byte-range
    /// pin flipping between the two statistics states, so both are checked.
    #[test]
    fn the_checkpoint_row_reads_are_driven_by_their_key_arrays() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            for (name, required, forbidden) in [
                (
                    "jvm_alias_owner_surface_by_identity",
                    "(blob_id=? AND identity_digest=?)",
                    "SCAN resolution_node_catalog",
                ),
                (
                    "jvm_alias_stage_owner_surface_by_identity",
                    "selected_resolution_stage_node_identity (host_ordinal=? AND identity_digest=?)",
                    "SCAN coordinate",
                ),
                (
                    "resolution_paths_by_key",
                    "SEARCH resolution_paths USING PRIMARY KEY (blob_id=? AND path=?)",
                    "SCAN resolution_paths",
                ),
                (
                    "resolution_identity_recipes",
                    "SEARCH resolution_identities USING INTEGER PRIMARY KEY (rowid=?)",
                    "SCAN resolution_identities",
                ),
                // Port block 2 (lane CM): every arm of the two candidate-match
                // statements seeks its own index, and the JSON array of
                // requests is what drives it.
                (
                    "resolution_forward_candidate_match",
                    "SEARCH p USING INDEX resolution_paths_forward (blob_id=? AND start_node=?",
                    "SCAN p",
                ),
                (
                    "resolution_reverse_candidate_match",
                    "SEARCH p USING INDEX resolution_paths_reverse (blob_id=? AND end_node=?",
                    "SCAN p",
                ),
                (
                    "resolution_reverse_candidate_match",
                    "SEARCH p USING INDEX resolution_paths_reverse_root_prefix (blob_id=? AND end_fixed_key",
                    "SCAN p",
                ),
                (
                    "resolution_reverse_candidate_match",
                    "SEARCH p USING INDEX resolution_paths_root_terminal (blob_id=? AND root_terminal=?)",
                    "SCAN p",
                ),
                (
                    "resolution_root_terminal_paths",
                    "SEARCH resolution_paths USING COVERING INDEX resolution_paths_root_terminal \
                     (blob_id=? AND root_terminal=?)",
                    "SCAN resolution_paths",
                ),
                (
                    "resolution_sites_by_key",
                    "SEARCH resolution_sites USING PRIMARY KEY (blob_id=? AND site=?)",
                    "SCAN resolution_sites",
                ),
                (
                    "resolution_scope_owners_by_node",
                    "(blob_id=? AND scope_head_node_key=?)",
                    "SCAN main.resolution_member_scope_properties",
                ),
                (
                    "resolution_member_scope_owners_by_node",
                    "(blob_id=? AND scope_head_node_key=?)",
                    "SCAN main.resolution_member_scope_properties",
                ),
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                assert!(
                    plan.iter().any(|row| row.contains(required)),
                    "{state} {name} must {required}: {plan:?}"
                );
                assert!(
                    !plan.iter().any(|row| row.contains(forbidden)),
                    "{state} {name} must not {forbidden}: {plan:?}"
                );
            }
        }
    }

    #[cfg(test)]
    /// The scoped endpoint-header read is driven by its mount scope.
    ///
    /// The point of binding the scope into the statement is that SQLite reads
    /// one primary-key row and one index range per scoped mount instead of
    /// scanning the direction's header rows and discarding all but the
    /// caller's crate in Rust. That is a property of the plan, not of the
    /// text, and it has to hold with and without `sqlite_stat1`: the whole
    /// reason plans are pinned here is that the same statement can be planned
    /// two ways.
    ///
    /// Two scopes drive it now. `root` is the root read's own mount array and
    /// `scope` is `temp.selected_resolution_scope_mounts`, the mounts the
    /// request may bind into at all, so the plan reads one primary-key row of
    /// each per array entry before it touches a header row. A mount the crate
    /// closure excludes drops out at the second seek and is never turned into
    /// an interior.
    #[test]
    #[hardwon("c3c6da88f35d: point requests read endpoint headers outside their selected mounts")]
    fn the_scoped_endpoint_header_read_is_driven_by_its_mount_scope() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(
                &conn,
                &pinned("selected_scoped_path_endpoint_header_mounts"),
            );
            for required in [
                "SCAN root VIRTUAL TABLE",
                "SEARCH scope USING PRIMARY KEY (mount_ordinal=?)",
                "SEARCH m USING PRIMARY KEY (mount_ordinal=?)",
                "INDEX resolution_path_endpoint_headers_keyed (blob_id=? AND direction=?)",
                "INDEX resolution_path_endpoint_headers_unkeyed (blob_id=? AND direction=?)",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(required)),
                    "{state} scoped endpoint header read must {required}: {plan:?}"
                );
            }
            for forbidden in ["SCAN h", "SCAN m", "SCAN scope"] {
                assert!(
                    !plan.iter().any(|row| row.contains(forbidden)),
                    "{state} scoped endpoint header read must not {forbidden}: {plan:?}"
                );
            }
        }
    }

    #[cfg(test)]
    /// The whole-selection endpoint-header read seeks the header shape its
    /// probe can match, so headers of other shapes cost it nothing.
    ///
    /// Its zero-fixed-symbol arm used to carry the wildcard in the same OR,
    /// which left `direction` as the only term the search index could seek:
    /// every execution walked the direction's whole header range, 3,461 times
    /// over twenty tract call sites for 527 ms. The noise here is headers of
    /// shapes no non-wildcard probe admits, in unmounted blobs, as most of
    /// tract's reverse headers are; each probe's VM work must not grow with
    /// them. The wildcard probe admits every header of its direction, so only
    /// its answer is checked.
    #[test]
    #[hardwon("75590eea5877: non-wildcard endpoint probes scanned headers of unrelated shapes")]
    fn the_unscoped_endpoint_header_read_seeks_its_probe_shape() {
        use rusqlite::StatementStatus;
        let sql = super::super::resolution_lexical::PATH_ENDPOINT_HEADER_MOUNTS_SQL;
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            // This is a populated access-plan fixture, not a publication fixture.
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .unwrap();
            prepare_pin_context(&conn);
            conn.execute_batch(
                "INSERT INTO temp.selected_resolution_mounts(mount_ordinal, blob_id)
                   VALUES (0, 1), (1, 2), (2, 3);
                 INSERT INTO temp.selected_resolution_scope_mounts(mount_ordinal)
                   VALUES (0), (1), (2);
                 INSERT INTO resolution_path_endpoint_headers(
                   blob_id, direction, identity_id, symbol_fixed_count, open_tail)
                   VALUES (1, 'forward', 7, 2, 1),
                          (2, 'reverse', NULL, 0, 1),
                          (3, 'reverse', NULL, 4, 0);",
            )
            .unwrap();
            let mut baseline = HashMap::new();
            for noise in [0_i64, 1024, 8192] {
                conn.execute(
                    "DELETE FROM resolution_path_endpoint_headers WHERE blob_id >= 1000",
                    [],
                )
                .unwrap();
                for key in 0..noise {
                    conn.execute(
                        "INSERT INTO resolution_path_endpoint_headers(
                           blob_id, direction, identity_id, symbol_fixed_count, open_tail)
                           VALUES (?1, 'forward', ?2, 2, 1), (?1, 'reverse', NULL, ?3, ?4)",
                        rusqlite::params![1000 + key, 100_000 + key, 3 + key % 5, key % 2],
                    )
                    .unwrap();
                }
                state.install(&conn);
                // (direction, first symbol, fixed symbols, open tail), answer, wildcard.
                type Probe = (&'static str, Option<i64>, i64, i64);
                let probes: [(Probe, &[i64], bool); 6] = [
                    (("forward", Some(7), 2, 0), &[0], false),
                    (("forward", Some(7), 1, 1), &[0], false),
                    (("forward", Some(99), 2, 0), &[], false),
                    (("reverse", None, 4, 0), &[1], false),
                    (("reverse", None, 0, 0), &[1], false),
                    (("forward", None, 0, 1), &[0], true),
                ];
                for (probe, expected, wildcard) in probes {
                    let bindings = rusqlite::params![probe.0, probe.1, probe.2, probe.3];
                    let plan = conn
                        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                        .unwrap()
                        .query_map(bindings, |row| row.get::<_, String>(3))
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    let mut statement = conn.prepare(sql).unwrap();
                    let mut actual = statement
                        .query_map(bindings, |row| row.get::<_, i64>(0))
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    actual.sort_unstable();
                    assert_eq!(actual, expected, "{state} probe={probe:?} noise={noise}");
                    if !wildcard {
                        let steps = statement.get_status(StatementStatus::VmStep);
                        let first = *baseline.entry(probe).or_insert(steps);
                        assert!(
                            steps <= first + first / 4 + 128,
                            "headers of other shapes changed the work of {probe:?}: {state} \
                             noise={noise} first={first} steps={steps} plan={plan:?}"
                        );
                    }
                    // The keyed arm may plan as one range or as a multi-index OR
                    // over its three fixed-count terms; both seek the identity.
                    for required in [
                        "resolution_path_endpoint_headers_search (direction=? AND identity_id=?",
                        "resolution_path_endpoint_headers_search (direction=? AND identity_id=? AND symbol_fixed_count=?)",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(required)),
                            "{state} unscoped endpoint header read must seek {required}: {plan:?}"
                        );
                    }
                    let direction_only = plan
                        .iter()
                        .filter(|row| {
                            row.contains("resolution_path_endpoint_headers_search (direction=?)")
                        })
                        .count();
                    assert!(
                        direction_only <= 1,
                        "{state} only the wildcard arm may read a whole direction: {plan:?}"
                    );
                    for forbidden in ["SCAN h", "SCAN m", "SCAN scope"] {
                        assert!(
                            !plan.iter().any(|row| row.contains(forbidden)),
                            "{state} unscoped endpoint header read must not {forbidden}: {plan:?}"
                        );
                    }
                }
            }
        }
    }

    #[cfg(test)]
    /// Both candidate gap-header reads are driven by the request's mount
    /// scope, and the unconditional one is covered by its index.
    ///
    /// The unconditional read used to bind `(direction, coverage_scope)` only,
    /// which made the header relation the outer loop: one execution walked
    /// every gap header the workspace held for that direction (122,728 rows on
    /// tract), seeked the table for a column it then discarded, and sorted the
    /// result in a temp b-tree. Both reads now drive from
    /// `temp.selected_resolution_scope_mounts` into `resolution_gaps` through
    /// a narrow partial index that leads on `covers`, so each is one covering
    /// seek per in-scope mount and a direction the workspace has no row of
    /// costs one trivial probe per mount rather than a descent through that
    /// blob's other gaps. That is a property of the plan, not of the text, and
    /// it has to hold with and without `sqlite_stat1`.
    /// A shared typed request reaches each member mount through its blob.
    /// The unique path index binds only the language here, and a plan through
    /// it walks every mount for every membership row (#3761).
    #[test]
    #[hardwon("#3761: shared typed lookups scanned every mount through the path index")]
    fn the_shared_typed_membership_reaches_mounts_by_blob() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("selected_typed_shared_membership"));
            assert!(
                plan.iter().any(|row| row.contains(
                    "SEARCH m USING INDEX selected_resolution_mounts_blob_ordinal (blob_id=?)"
                )),
                "{state} must reach the mount by its blob: {plan:?}"
            );
            assert!(
                !plan.iter().any(|row| row.contains("SCAN m")),
                "{state} must not scan the mounts: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("4f3061857f8c: fragment gap reads scanned unrelated headers outside the mount scope")]
    fn the_candidate_gap_header_reads_are_driven_by_their_mount_scope() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            for (name, header_search) in [
                (
                    "selected_unconditional_candidate_gap_reasons",
                    "SEARCH h USING COVERING INDEX resolution_gaps_fragment_wide (covers=? AND blob_id=?)",
                ),
                (
                    "selected_boundary_candidate_gap_branches",
                    "SEARCH h USING COVERING INDEX resolution_gaps_root_branches (covers=? AND blob_id=? AND lookup=?)",
                ),
                (
                    "selected_boundary_candidate_gap_branches_all",
                    "SEARCH h USING COVERING INDEX resolution_gaps_root_branches (covers=? AND blob_id=?)",
                ),
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                for required in [
                    "SCAN scope",
                    "SEARCH m USING PRIMARY KEY (mount_ordinal=?)",
                    header_search,
                ] {
                    assert!(
                        plan.iter().any(|row| row.contains(required)),
                        "{state} {name} must {required}: {plan:?}"
                    );
                }
                for forbidden in ["SCAN h", "SCAN m", "TEMP B-TREE"] {
                    assert!(
                        !plan.iter().any(|row| row.contains(forbidden)),
                        "{state} {name} must not {forbidden}: {plan:?}"
                    );
                }
            }
            // A scoped visit reads only its named mounts: the mount list
            // drives, the request-scope table is seeked, never scanned.
            for (name, header_search) in [
                (
                    "selected_unconditional_candidate_gap_reasons_in_mounts",
                    "SEARCH h USING COVERING INDEX resolution_gaps_fragment_wide (covers=? AND blob_id=?)",
                ),
                (
                    "selected_boundary_candidate_gap_branches_in_mounts",
                    "SEARCH h USING COVERING INDEX resolution_gaps_root_branches (covers=? AND blob_id=? AND lookup=?)",
                ),
                (
                    "selected_boundary_candidate_gap_branches_all_in_mounts",
                    "SEARCH h USING COVERING INDEX resolution_gaps_root_branches (covers=? AND blob_id=?)",
                ),
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                for required in [
                    "SEARCH scope USING PRIMARY KEY (mount_ordinal=?)",
                    "SEARCH m USING PRIMARY KEY (mount_ordinal=?)",
                    header_search,
                ] {
                    assert!(
                        plan.iter().any(|row| row.contains(required)),
                        "{state} {name} must {required}: {plan:?}"
                    );
                }
                if name == "selected_unconditional_candidate_gap_reasons_in_mounts" {
                    assert!(plan.iter().any(|row| row.contains(
                        "SEARCH absent USING COVERING INDEX resolution_gaps_fragment_wide (covers=?)"
                    )), "{state} {name} must seek the direction-wide emptiness proof: {plan:?}");
                }
                for forbidden in [
                    "SCAN scope",
                    "SCAN h",
                    "SCAN m",
                    "SCAN absent",
                    "TEMP B-TREE",
                ] {
                    assert!(
                        !plan.iter().any(|row| row.contains(forbidden)),
                        "{state} {name} must not {forbidden}: {plan:?}"
                    );
                }
            }
            // The per-endpoint branch read is keyed, not scoped: its caller
            // holds the blob and the endpoint nodes, so it seeks the primary
            // key for each node of one JSON array and never scans the table.
            let name = "selected_endpoint_candidate_gap_branches";
            let plan = explain_pin(&conn, &pinned(name));
            assert!(
                plan.iter().any(|row| row
                    .contains("SEARCH h USING PRIMARY KEY (blob_id=? AND covers=? AND subject=?)")),
                "{state} {name} must seek its endpoint keys: {plan:?}"
            );
            assert!(
                plan.iter().any(|row| row.contains(
                    "SEARCH h USING PRIMARY KEY (blob_id=? AND covers=? AND subject=? AND lookup=?)"
                )),
                "{state} {name} must seek exact lookup keys: {plan:?}"
            );
            for forbidden in ["SCAN h", "TEMP B-TREE"] {
                assert!(
                    !plan.iter().any(|row| row.contains(forbidden)),
                    "{state} {name} must not {forbidden}: {plan:?}"
                );
            }
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "ed9135b9cc0a: definition hydration scanned blob-wide units instead of requested keys"
    )]
    fn selected_definition_units_seek_the_complete_requested_keys() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("selected_definition_units"));
            for seek in [
                "SEARCH crosswalk USING PRIMARY KEY (blob_id=? AND definition_semantic_key=?)",
                "SEARCH units USING PRIMARY KEY (blob_id=? AND unit_key=?)",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(seek)),
                    "{state}: {seek}: {plan:?}"
                );
            }
            assert!(
                plan.first().is_some_and(|row| row.contains("SCAN request")),
                "{state}: requested coordinates drive hydration: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "#6291: JVM package selection enumerated unrelated hosts instead of seeking requested names"
    )]
    fn jvm_package_member_hosts_seek_shared_names_in_both_statistics_states() {
        let store = AnalyzerStore::open_ephemeral().expect("open store");
        let conn = store.conn.lock().expect("store mutex");
        prepare_pin_context(&conn);
        // This fixture exercises planner cardinalities without publishing facts.
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            WITH RECURSIVE blobs(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM blobs WHERE n<64),
            names(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM names WHERE n<64)
            INSERT INTO resolution_semantic_catalog(blob_id,local_key,shared_identity)
            SELECT blobs.n,names.n,names.n FROM blobs CROSS JOIN names;
            WITH RECURSIVE blobs(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM blobs WHERE n<64),
            names(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM names WHERE n<64)
            INSERT INTO resolution_semantic_catalog(blob_id,local_key,identity_digest)
            SELECT blobs.n,names.n+1000,CAST(printf('%032d', names.n) AS BLOB) FROM blobs CROSS JOIN names;
            INSERT INTO resolution_package_members(blob_id,token_key,definition_key,domain_key,source_site,root_scope_key,namespace,lookup_key)
            SELECT DISTINCT blob_id,1,1,1,0,0,'type',1 FROM resolution_semantic_catalog;
            INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,file_version_id,storage_language,semantic_language)
            SELECT DISTINCT blob_id,blob_id,NULL,'java','java' FROM resolution_semantic_catalog;
            INSERT INTO selected_resolution_scope_mounts SELECT mount_ordinal FROM selected_resolution_mounts;
            INSERT INTO blob_meta(blob_id,lang,contains_tests,content_package,stored_unit_count,range_count,signature_count,signature_metadata_count,supertype_count,child_count,import_statement_count,type_identifier_count,is_complete)
            SELECT blob_id,'java',0,'dep',0,0,0,0,0,0,0,0,1 FROM selected_resolution_mounts;").unwrap();
        conn.execute_batch("INSERT INTO resolution_supertypes(blob_id,definition,kind,reference,frontier,parent_ordinal)
            SELECT blob_id,1,0,1,0,0 FROM selected_resolution_mounts;
            UPDATE resolution_semantic_catalog SET import_route_kind='type_on_demand',import_source_site=1,import_start_byte=0,import_end_byte=1 WHERE local_key=1001;
            INSERT INTO resolution_import_selectors(blob_id,site,kind) SELECT blob_id,1,'star' FROM selected_resolution_mounts;
            INSERT INTO selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest)
            SELECT blob_id,blob_id,CAST(printf('%032d',blob_id) AS BLOB),CAST(printf('%032d',blob_id) AS BLOB) FROM selected_resolution_mounts;
            INSERT INTO selected_resolution_stage_semantic_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest)
            SELECT blob_id,blob_id,0,blob_id*4294967296+1001,CAST(printf('%032d',blob_id) AS BLOB) FROM selected_resolution_mounts;").unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for query in pinned_queries()
                .into_iter()
                .filter(|query| query.name.starts_with("jvm_named_package_member_targets_"))
            {
                let plan = explain_pin(&conn, &query);
                for seek in [
                    "SEARCH lookup USING COVERING INDEX resolution_semantic_catalog_shared_identity (shared_identity=?)",
                    "SEARCH member USING COVERING INDEX resolution_package_members_lookup (blob_id=? AND lookup_key=?)",
                    "SEARCH mounted USING INDEX selected_resolution_mounts_blob_ordinal (blob_id=?)",
                ] {
                    assert!(
                        plan.iter().any(|step| step.contains(seek)),
                        "{state} {}: {seek}: {plan:?}",
                        query.name
                    );
                }
                for forbidden in ["SCAN lookup", "SCAN member", "AUTOMATIC", "TEMP B-TREE"] {
                    assert!(
                        plan.iter().all(|step| !step.contains(forbidden)),
                        "{state} {}: {forbidden}: {plan:?}",
                        query.name
                    );
                }
                let count = conn
                    .prepare(&query.sql)
                    .unwrap()
                    .query_map(rusqlite::params_from_iter(query.params.iter()), |_| Ok(()))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                    .len();
                assert_eq!(
                    count,
                    if query.name.contains("java_peers") {
                        0
                    } else {
                        64
                    }
                );
            }
            for name in [
                "jvm_preparation_supertype_membership",
                "import_token_metadata",
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                let required = if name == "jvm_preparation_supertype_membership" {
                    vec!["resolution_supertypes_reference (blob_id=? AND reference=?)"]
                } else {
                    vec![
                        "SEARCH catalog USING PRIMARY KEY (blob_id=? AND local_key=?)",
                        "SEARCH selector USING PRIMARY KEY (blob_id=? AND site=?)",
                        "selected_resolution_stage_semantic_runtime (runtime_key=? AND shared_id=? AND host_ordinal=?)",
                    ]
                };
                for seek in required {
                    assert!(
                        plan.iter().any(|step| step.contains(seek)),
                        "{state} {name}: {seek}: {plan:?}"
                    );
                }
                for forbidden in [
                    "SCAN catalog",
                    "SCAN selector",
                    "SCAN staged",
                    "SCAN resolution_supertypes",
                    "AUTOMATIC",
                    "TEMP B-TREE",
                ] {
                    assert!(
                        plan.iter().all(|step| !step.contains(forbidden)),
                        "{state} {name}: {forbidden}: {plan:?}"
                    );
                }
            }
            // #6291: eligible alias hosts retain indexed package membership and
            // transient metadata access before full mount records are decoded.
            for query in pinned_queries()
                .into_iter()
                .filter(|query| query.name.starts_with("jvm_eligible_import_targets_"))
            {
                let plan = explain_pin(&conn, &query);
                for seek in [
                    "idx_workspace_file_package_rows_name (package_name=?)",
                    "SEARCH meta USING PRIMARY KEY (blob_id=?)",
                ] {
                    assert!(
                        plan.iter().any(|step| step.contains(seek)),
                        "{state} {}: {seek}: {plan:?}",
                        query.name
                    );
                }
                for forbidden in ["SCAN package", "SCAN meta", "AUTOMATIC", "TEMP B-TREE"] {
                    assert!(
                        plan.iter().all(|step| !step.contains(forbidden)),
                        "{state} {}: {forbidden}: {plan:?}",
                        query.name
                    );
                }
                let rows = conn
                    .prepare(&query.sql)
                    .unwrap()
                    .query_map(rusqlite::params_from_iter(query.params.iter()), |_| Ok(()))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows.len(),
                    if query.name.ends_with("java_peers") {
                        0
                    } else {
                        64
                    },
                    "{state} {}",
                    query.name
                );
            }
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#5658: macro admission and matching decoded every invocation's tokens")]
    fn selected_macro_input_reads_seek_blob_and_invocation_in_both_statistics_states() {
        let store = AnalyzerStore::open_ephemeral().expect("open store");
        let conn = store.conn.lock().expect("store mutex");
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            WITH RECURSIVE blobs(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM blobs WHERE n<64),
            invocations(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM invocations WHERE n<8)
            INSERT INTO source_rust_macro_inputs(blob_id,invocation_occurrence_id,start_byte,source,invocation_start_byte)
            SELECT blobs.n,invocations.n,invocations.n*8,'(x)',invocations.n*8-1 FROM blobs CROSS JOIN invocations;
            WITH ordinals(n) AS (VALUES(0),(1))
            INSERT INTO source_rust_macro_input_tokens(blob_id,invocation_occurrence_id,ordinal,source_occurrence_id,parent_ordinal,syntax_kind,start_byte,end_byte)
            SELECT blob_id,invocation_occurrence_id,n,n,CASE n WHEN 0 THEN NULL ELSE 0 END,'token_tree',start_byte,start_byte+3
            FROM source_rust_macro_inputs CROSS JOIN ordinals;").unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for name in [
                "rust_macro_input_exists",
                "rust_macro_invocation_input",
                "rust_macro_invocation_tokens",
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                assert!(
                    plan.iter()
                        .any(|row| row.contains("SEARCH source_rust_macro_")),
                    "{state} {name}: {plan:?}"
                );
                for forbidden in ["SCAN source_rust_macro_", "TEMP B-TREE", "AUTOMATIC"] {
                    assert!(
                        plan.iter().all(|row| !row.contains(forbidden)),
                        "{state} {name}: {plan:?}"
                    );
                }
                if name == "rust_macro_invocation_tokens" {
                    assert!(
                        plan.iter().any(|row| row.contains(
                            "USING PRIMARY KEY (blob_id=? AND invocation_occurrence_id=?)"
                        )),
                        "{state} {name}: {plan:?}"
                    );
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#4501: macro occurrence line reads repeated a JSONB arena lookup per input")]
    fn selected_macro_occurrence_lines_seek_one_arena_in_both_statistics_states() {
        let store = AnalyzerStore::open_ephemeral().expect("open store");
        let conn = store.conn.lock().expect("store mutex");
        conn.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        conn.execute(
            "INSERT INTO source_occurrence_arenas VALUES(1,jsonb('[[0,1,1,1,0]]'))",
            [],
        )
        .unwrap();

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("selected_macro_occurrence_lines"));
            assert!(
                plan.iter()
                    .any(|row| row.contains("SEARCH arena USING PRIMARY KEY (blob_id=?)")),
                "{state}: the arena lookup must use its blob primary key: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.contains("SCAN entry VIRTUAL TABLE")),
                "{state}: the selected arena is traversed once with json_each: {plan:?}"
            );
            assert!(
                plan.iter().all(|row| !row.contains("SCAN arena")),
                "{state}: the arena table must not be scanned: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn type_productions_preserve_length_constraints_and_use_output_seeks() {
        let store = AnalyzerStore::open_ephemeral().expect("open store");
        let conn = store.conn.lock().expect("store mutex");
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            WITH RECURSIVE slots(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM slots WHERE n<256)
            INSERT INTO resolution_type_productions(blob_id,output_slot,element_slot,constructor,length_token)
            SELECT 1,n,n+256,3,NULL FROM slots;").unwrap();
        assert!(
            conn.execute(
                "INSERT INTO resolution_type_productions VALUES(1,1000,1001,4,NULL)",
                []
            )
            .is_err(),
            "array length is required"
        );
        assert!(
            conn.execute(
                "INSERT INTO resolution_type_productions VALUES(1,1000,1001,3,'4')",
                []
            )
            .is_err(),
            "slice cannot carry an array length"
        );
        conn.execute(
            "INSERT INTO resolution_type_productions VALUES(1,1000,1001,4,'0x04')",
            [],
        )
        .unwrap();
        assert_eq!(conn.query_row("SELECT length_token FROM resolution_type_productions WHERE blob_id=1 AND output_slot=1000", [], |row| row.get::<_, String>(0)).unwrap(), "0x04");
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("type_productions_by_output"));
            assert!(plan.iter().any(|row| row.contains("SEARCH resolution_type_productions USING PRIMARY KEY (blob_id=? AND output_slot=?)")), "{state}: {plan:?}");
            assert!(
                plan.iter()
                    .all(|row| !row.contains("SCAN resolution_type_productions")
                        && !row.contains("AUTOMATIC")
                        && !row.contains("TEMP B-TREE")),
                "{state}: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "#5133: dependency export witnesses missed the alias-target index and scanned module exports"
    )]
    fn rust_dependency_reexport_witness_seeks_target_coordinates_in_both_statistics_states() {
        use rusqlite::{params, params_from_iter};

        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            let pin = pinned("rust_unit_summary_dependency_reexport_witness");
            // A selected dependency among unrelated summaries, each with both
            // declarations and aliases. Bind the registry's real target shape.
            for summary in 1..=16 {
                let key = vec![summary as u8; 32];
                conn.execute(
                    "INSERT INTO resolution_unit_summaries(
                       summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,
                       derivation_version,complete,output_digest,publication_state)
                     VALUES(?1,'rust','rust_crate',?2,?2,?3,?4,1,?2,'complete')",
                    params![summary, key, pin.params[5], pin.params[6]],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO resolution_unit_summary_versions
                     (workspace_id,lang,generation,unit_key,valid_from,valid_until,summary_id)
                     VALUES(?1,'rust',1,?2,1,NULL,?3)",
                    params![pin.params[0], key, summary],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO rust_crate_topologies(
                       topology_id,topology_digest,crate_key,producer_epoch,target_kind,
                       crate_name,edition,prelude,cfg_atoms,inventory_complete,
                       export_surface_digest,publication_state)
                     VALUES(?1,?2,?2,'rust-resolution-epoch','lib','planner_fixture',
                            '2021','std',jsonb('[]'),1,?2,'complete')",
                    params![summary, key],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO rust_resolution_unit_summary_versions
                     (workspace_id,lang,generation,unit_key,valid_from,summary_id,manifest_file_version_id,topology_id)
                     VALUES(?1,'rust',1,?2,1,?3,NULL,?4)",
                    params![pin.params[0], key, summary, summary + 1],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO rust_crate_versions
                     VALUES(?1,'rust',1,?2,1,NULL,NULL,?3)",
                    params![pin.params[0], key, summary],
                )
                .unwrap();
                conn.execute(
                    "WITH RECURSIVE names(n) AS (
                       VALUES(1) UNION ALL SELECT n+1 FROM names WHERE n<128
                     )
                     INSERT INTO rust_resolution_unit_summary_exports(
                       summary_id,module_path,namespace,name,identity_id,visibility,origin,
                       target_unit_key,alias_identity_id,target_module_path,target_name)
                     SELECT ?1,'crate','value','alias_'||n,1,'public','reexport',
                            ?2,1,'crate::api::nested','item_'||n FROM names",
                    params![summary, pin.params[7]],
                )
                .unwrap();
                conn.execute(
                    "WITH RECURSIVE names(n) AS (
                       VALUES(1) UNION ALL SELECT n+1 FROM names WHERE n<128
                     )
                     INSERT INTO rust_resolution_unit_summary_exports(
                       summary_id,module_path,namespace,name,identity_id,visibility,origin)
                     SELECT ?1,'crate','value','local_'||n,1,'public','declaration' FROM names",
                    [summary],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_exports(
                   summary_id,module_path,namespace,name,identity_id,visibility,origin,
                   target_unit_key,alias_identity_id,target_module_path,target_name)
                 VALUES(1,'crate','value','item',1,'public','reexport',
                        ?1,1,'crate::api::nested','item')",
                [&pin.params[7]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO rust_crate_public_module_reachability
                 VALUES(1,?1,'crate::api::nested')",
                [&pin.params[7]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO rust_crate_public_module_reachability
                 VALUES(2,?1,'crate::api::nested'),(1,?2,'crate::api::decoy')",
                params![pin.params[7], vec![99_u8; 32]],
            )
            .unwrap();
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            for expected in [
                "SEARCH versions USING PRIMARY KEY (workspace_id=? AND lang=? AND generation=? AND crate_key=? AND valid_from<?)",
                "SEARCH topology USING INTEGER PRIMARY KEY (rowid=?)",
                "SEARCH reachability USING PRIMARY KEY (topology_id=? AND target_crate_key=? AND target_module_path=?)",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(expected)),
                    "{state} {expected}: {plan:?}"
                );
            }
            assert!(
                plan.iter().any(|row| {
                    row.starts_with("SEARCH exports USING")
                        && row.contains("(target_unit_key=? AND target_module_path=? AND target_name=? AND namespace=? AND alias_identity_id=? AND summary_id=?)")
                }),
                "{state}: alias witnesses must seek target coordinates in the selected summary: {plan:?}"
            );
            assert!(
                plan.iter().all(|row| {
                    ![
                        "SCAN exports",
                        "SCAN exported_module",
                        "SCAN versions",
                        "SCAN reachability",
                        "AUTOMATIC",
                        "TEMP B-TREE",
                    ]
                    .iter()
                    .any(|forbidden| row.contains(forbidden))
                }),
                "{state} export witness must seek base rows without transient indexes: {plan:?}"
            );
            let witnessed = || {
                conn.query_row(&pin.sql, params_from_iter(&pin.params), |row| {
                    row.get::<_, bool>(0)
                })
                .unwrap()
            };
            assert!(witnessed(), "{state}: exact public alias");
            conn.execute(
                "DELETE FROM rust_resolution_unit_summary_exports WHERE name='item'",
                [],
            )
            .unwrap();
            assert!(
                witnessed(),
                "{state}: selected topology proves the canonical target module"
            );
            conn.execute(
                "DELETE FROM rust_crate_public_module_reachability
                 WHERE topology_id=1 AND target_crate_key=?1 AND target_module_path=?2",
                params![pin.params[7], pin.params[8]],
            )
            .unwrap();
            assert!(
                !witnessed(),
                "{state}: membership in another topology is not a proof"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn rust_named_reexport_targets_seek_populated_binders_in_both_statistics_states() {
        use rusqlite::{params, params_from_iter};

        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            let pin = pinned("rust_crate_named_reexport_targets");
            conn.execute_batch(
                "INSERT INTO rust_crate_topologies VALUES(
                   1,zeroblob(32),zeroblob(32),'test','lib','sample','2021','std',
                   jsonb('[\"test\"]'),1,zeroblob(32),'complete');
                 INSERT INTO rust_crate_containers VALUES(1,'crate','module','root');",
            )
            .unwrap();
            for blob_id in 1..=16 {
                conn.execute(
                    "INSERT INTO rust_crate_container_sources
                     VALUES(1,'crate',?1,0,?2,'declared',NULL,NULL)",
                    params![blob_id, format!("src/lib_{blob_id}.rs")],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO source_rust_module_scopes
                     (blob_id,ordinal,parent_ordinal,declaration_id,module_name,imports_macros,resolution_scope)
                     VALUES(?1,0,NULL,NULL,'crate',0,0)",
                    [blob_id],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO source_rust_import_contexts
                     (declaration_start_byte,declaration_end_byte,blob_id,declaration_occurrence_id,
                      owner_module,owner_scope_occurrence_id,visibility,cfg_condition,native_scope,
                      owner_scope_start_byte,owner_scope_end_byte)
                     VALUES(0,0,?1,0,'crate',0,'public','always',0,0,0)",
                    [blob_id],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO source_imports
                     (blob_id,import_id,statement,is_wildcard,is_global,identifier,path_kind,
                      declaration_occurrence_id,declaration_start_byte,declaration_end_byte)
                     VALUES(?1,0,'use crate::dep::Target;',0,0,'Target','namespace',0,0,0)",
                    [blob_id],
                )
                .unwrap();
                for ordinal in 0..64 {
                    let bound_name = if blob_id == 1 && ordinal == 0 {
                        "selected".to_owned()
                    } else {
                        format!("decoy_{blob_id}_{ordinal}")
                    };
                    conn.execute(
                        "INSERT INTO rust_import_targets
                         (blob_id,lang,ordinal,source_import_id,source_context_occurrence_id,
                          module_path,bound_name,imported_name,is_glob,visibility,cfg_condition,
                          is_extern_crate,is_macro_use,leading_absolute)
                         VALUES(?1,'rust',?2,0,0,'crate',?3,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
                        params![blob_id, ordinal, bound_name],
                    )
                    .unwrap();
                    conn.execute(
                        "INSERT INTO rust_crate_imports
                         VALUES(1,'crate','type',?1,?2,?3,0,zeroblob(32),'crate::dep','Target')",
                        params![bound_name, blob_id, ordinal],
                    )
                    .unwrap();
                }
            }

            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            for expected in [
                "SEARCH target USING PRIMARY KEY (blob_id=? AND ordinal=?)",
                "SEARCH member USING PRIMARY KEY (topology_id=? AND container_path=? AND blob_id=?)",
                "SEARCH scope USING PRIMARY KEY (blob_id=? AND ordinal=?)",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(expected)),
                    "{state} {expected}: {plan:?}"
                );
            }
            assert!(
                plan.iter().all(|row| {
                    ![
                        "SCAN imports",
                        "SCAN target",
                        "SCAN source",
                        "SCAN context",
                        "SCAN member",
                        "SCAN scope",
                        "AUTOMATIC",
                    ]
                    .iter()
                    .any(|forbidden| row.contains(forbidden))
                }),
                "{state} named reexport target lookup must seek populated source rows: {plan:?}"
            );
            // Both the primary key and binder index bound work to this
            // topology/module frame; their remaining columns differ.
            assert!(
                plan.iter().any(|row| {
                    row.starts_with("SEARCH imports USING")
                        && row.contains("(topology_id=? AND module_path=?")
                }),
                "{state}: imports must seek the selected topology and module: {plan:?}"
            );
            let targets = conn
                .prepare(&pin.sql)
                .unwrap()
                .query_map(params_from_iter(&pin.params), |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(targets.len(), 1, "{state}: selected binder only");
            assert_eq!(targets[0].1, "crate::dep");
            assert_eq!(targets[0].2, "Target");
        }
    }

    #[cfg(test)]
    #[test]
    fn jvm_native_alias_declaration_gaps_use_keyed_reads_in_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            conn.execute_batch("PRAGMA foreign_keys=OFF;")
                .expect("access-plan fixture does not publish fragments");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);

            let unsupported_scope_or_binder =
                super::super::resolution_prepare::resolution_rows::gap_origin_code(
                    crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder,
                    ),
                );
            conn.execute_batch(
                "INSERT INTO resolution_node_catalog(blob_id,local_key,identity_digest,source_scope,kind) VALUES
                   (1,33,randomblob(32),33,0),(1,17,randomblob(32),NULL,1),
                   (1,34,randomblob(32),34,0),(1,18,randomblob(32),NULL,1);",
            )
            .expect("matching declaration and unrelated scope");
            conn.execute(
                "INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_identity,start_lead_scoped,end_node,end_lead_scoped,body)
                 VALUES(1,1,33,1,0,17,0,jsonb('[[],null,[],null,[],null,[],null,[],[],[]]'))",
                [],
            )
            .expect("matching source-proven binder");
            conn.execute(
                "INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES
                   (1,6,17,0,1,101),(1,5,33,0,2,102)",
                [],
            )
            .expect("matching declaration and binder gaps");
            conn.execute(
                "INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES
                   (1,101,17,?1),(1,102,33,?1)",
                [unsupported_scope_or_binder],
            )
            .expect("matching gap provenance");

            // Keep the target sparse among realistic keyed noise. Most rows
            // belong to other blobs, definitions, and scopes; same-blob rows
            // exercise the reverse index and gap/reason primary keys.
            for index in 0..1024_i64 {
                let blob = if index % 2 == 0 { 1 } else { 2 };
                let start = 10_000 + index;
                let end = 20_000 + index;
                conn.execute(
                    "INSERT INTO resolution_node_catalog(blob_id,local_key,identity_digest,source_scope,kind)
                     VALUES(?1,?2,randomblob(32),?3,0)",
                    rusqlite::params![blob, start, start],
                )
                .expect("unrelated scope and definition");
                conn.execute(
                    "INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_identity,start_lead_scoped,end_node,end_lead_scoped,body)
                     VALUES(?1,?2,?3,?4,0,?5,0,jsonb('[[],null,[],null,[],null,[],null,[],[],[]]'))",
                    rusqlite::params![blob, 10 + index, start, 10 + index, end],
                )
                .expect("unrelated binder path");
                conn.execute(
                    "INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES
                       (?1,5,?2,0,?3,?4),(?1,6,?5,0,?3+1,?4)",
                    rusqlite::params![blob, start, 10 + 2 * index, 10_000 + index, end],
                )
                .expect("unrelated scoped declaration gap");
                conn.execute(
                    "INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES(?1,?2,?3,?4)",
                    rusqlite::params![blob, 10_000 + index, start, unsupported_scope_or_binder],
                )
                .expect("unrelated gap provenance");
            }

            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("jvm_native_alias_declaration_gaps"));

            for required in [
                "SEARCH binder USING INDEX resolution_paths_reverse (blob_id=? AND end_node=?",
                "SEARCH gap USING PRIMARY KEY",
                "SEARCH reason USING PRIMARY KEY",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(required)),
                    "{state} must {required}: {plan:?}"
                );
            }
            for forbidden in [
                "SCAN binder",
                "SCAN gap",
                "SCAN reason",
                "SCAN resolution_paths",
                "AUTOMATIC",
                "TEMP B-TREE",
            ] {
                assert!(
                    !plan.iter().any(|row| row.contains(forbidden)),
                    "{state} must not {forbidden}: {plan:?}"
                );
            }

            let mut reasons = conn
                .prepare(&pinned("jvm_native_alias_declaration_gaps").sql)
                .expect("prepare selected reasons")
                .query_map(
                    rusqlite::params![1, 17, unsupported_scope_or_binder],
                    |row| row.get::<_, i64>(0),
                )
                .expect("read selected reasons")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect selected reasons");
            reasons.sort_unstable();
            assert_eq!(reasons, [101, 102], "{state}: exact declaration gaps");
        }
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#6594: selected typed keys paid a DELETE and per-key INSERT before every read")]
    fn typed_request_arrays_keep_indexed_corpus_probes() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            prepare_pin_context(&conn);
            state.install(&conn);
            for arity in [1, 256] {
                let requests =
                    serde_json::to_string(&(0..arity).map(|key| [0, key]).collect::<Vec<_>>())
                        .unwrap();
                for name in [
                    "generic_parameter_declarations",
                    "go_member_declarations",
                    "java_access_endpoints",
                    "jvm_access_endpoints",
                    "scala_reference_endpoints",
                    "java_inheritance_declarations",
                    "java_synthetic_type_bodies",
                    "selected_definition_units",
                    "selected_lexical_definitions",
                    "selected_declaration_units",
                ] {
                    let mut query = pinned(name);
                    query.params[0] = rusqlite::types::Value::Text(requests.clone());
                    let plan = explain_pin(&conn, &query);
                    eprintln!("{state:?} arity={arity} {name}: {plan:?}");
                    if matches!(
                        name,
                        "selected_definition_units" | "selected_declaration_units"
                    ) {
                        assert!(
                            !plan.iter().any(|row| row.contains("TEMP B-TREE")),
                            "{state:?} {name} must stream sorted request coordinates: {plan:?}"
                        );
                    }
                    let request = plan
                        .iter()
                        .position(|row| row.starts_with("SCAN request VIRTUAL TABLE"))
                        .unwrap_or_else(|| panic!("{state:?} {name}: {plan:?}"));
                    for alias in ["mount", "interior"] {
                        let probe = plan
                            .iter()
                            .position(|row| row.starts_with(&format!("SEARCH {alias} ")))
                            .unwrap_or_else(|| panic!("{state:?} {name}: {plan:?}"));
                        assert!(request < probe, "{state:?} {name}: {plan:?}");
                        assert!(
                            !plan
                                .iter()
                                .any(|row| row.starts_with(&format!("SCAN {alias}"))),
                            "{state:?} {name}: {plan:?}"
                        );
                    }
                    // Scala materializes its query-local templates CTE and
                    // has always indexed that bounded result automatically.
                    // Corpus probes must keep using their stored indexes.
                    assert!(
                        plan.iter().all(|row| !row.contains("AUTOMATIC")
                            || row.starts_with("SEARCH templates ")),
                        "{state:?} {name}: {plan:?}"
                    );
                }
            }
        }
    }

    #[cfg(test)]
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
                if query.name == "rust_unit_summary_package_members" {
                    assert!(
                        plan.iter()
                            .any(|detail| detail.contains("SEARCH versions USING PRIMARY KEY")),
                        "{state} package-member lookup must seek live summary versions: {plan:?}"
                    );
                    assert!(
                        plan.iter()
                            .any(|detail| detail.contains("SEARCH members USING PRIMARY KEY")),
                        "{state} package-member lookup must seek summary members: {plan:?}"
                    );
                    assert!(
                        plan.iter().all(|detail| {
                            !detail.contains("AUTOMATIC")
                                && !detail.contains("TEMP B-TREE")
                                && !detail.starts_with("SCAN versions")
                                && !detail.starts_with("SCAN members")
                                && !detail.starts_with("SCAN contexts")
                                && !detail.starts_with("SCAN naming")
                        }),
                        "{state} package-member lookup must not scan unbounded rows or build planner state: {plan:?}"
                    );
                }
                if query.name == "rust_unit_summary_cargo_routes" {
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("resolution_unit_summary_versions_open")
                                || detail
                                    .contains("sqlite_autoindex_resolution_unit_summary_versions_1")
                                || detail.contains("SEARCH versions USING PRIMARY KEY")
                        }),
                        "{state} Cargo-route lookup must seek selected summary versions: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("SEARCH parent_member USING")
                                && detail.contains("PRIMARY KEY")
                        }),
                        "{state} Cargo-route lookup must seek the parent root member by summary: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("SEARCH child_versions USING PRIMARY KEY")
                        }),
                        "{state} Cargo-route lookup must seek the live dependency summary by unit key: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("SEARCH child_member USING")
                                && detail.contains("PRIMARY KEY")
                        }),
                        "{state} Cargo-route lookup must seek the child root member by summary: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("SEARCH parent_file USING INDEX idx_workspace_file_versions_snapshot_kind")
                                || detail.contains("SEARCH parent_file USING INDEX sqlite_autoindex_workspace_file_versions_1")
                        }),
                        "{state} Cargo-route lookup must seek the parent's live root file version: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("SEARCH child_file USING INDEX idx_workspace_file_versions_snapshot_kind")
                                || detail.contains("SEARCH child_file USING INDEX sqlite_autoindex_workspace_file_versions_1")
                        }),
                        "{state} Cargo-route lookup must seek the dependency's live root file version: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("SEARCH dependencies USING")
                                && detail.contains("PRIMARY KEY")
                        }),
                        "{state} Cargo-route lookup must seek dependency rows by summary: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("resolution_unit_summary_dependency_names_ordinal")
                        }),
                        "{state} Cargo-route lookup must seek dependency names by ordinal: {plan:?}"
                    );
                    assert!(
                        plan.iter().all(|detail| {
                            !detail.contains("AUTOMATIC")
                                && !detail.contains("TEMP B-TREE")
                                && !detail.starts_with("SCAN versions")
                                && !detail.starts_with("SCAN members")
                                && !detail.starts_with("SCAN dependencies")
                                && !detail.starts_with("SCAN dependency_names")
                                && !detail.starts_with("SCAN parent_member")
                                && !detail.starts_with("SCAN child_member")
                                && !detail.starts_with("SCAN child_versions")
                                && !detail.starts_with("SCAN parent_file")
                                && !detail.starts_with("SCAN child_file")
                        }),
                        "{state} Cargo-route lookup must not scan unbounded base rows or create indexes: {plan:?}"
                    );
                }
                if query.name == "rust_unit_summary_development_capability" {
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("SEARCH topologies USING INTEGER PRIMARY KEY")
                        }),
                        "{state} Rust target capability lookup must seek its topology: {plan:?}"
                    );
                    assert!(
                        plan.iter()
                            .any(|detail| { detail.contains("rust_crate_versions_topology") }),
                        "{state} Rust target capability lookup must seek the topology version: {plan:?}"
                    );
                    assert!(
                        plan.iter().all(|detail| {
                            !detail.contains("SCAN topologies")
                                && !detail.contains("SCAN versions")
                                && !detail.contains("AUTOMATIC")
                                && !detail.contains("TEMP B-TREE")
                        }),
                        "{state} Rust target capability lookup must stay indexed: {plan:?}"
                    );
                }
                if RUST_MACRO_WALK_QUERIES.contains(&query.name.as_str()) {
                    // A query reads its source path through the selected mount, or
                    // through the selected file version of the persisted path when
                    // it never reads a mount (the child-module walk).
                    assert!(
                        plan.iter().any(|detail| detail
                            .contains("sqlite_autoindex_selected_resolution_mounts_2")
                            || detail.contains("idx_workspace_file_versions_snapshot_kind")),
                        "{state} {} must seek its selected source path: {plan:?}",
                        query.name
                    );
                    // Membership is a keyed seek: by selected blob, or by the summary
                    // when the query reaches members through the selected file version.
                    assert!(
                        plan.iter().any(|detail| {
                            detail.contains("resolution_unit_summary_members_blob")
                                || detail
                                    .contains("SEARCH members USING PRIMARY KEY (summary_id=?)")
                        }),
                        "{state} {} must seek summary membership by a key: {plan:?}",
                        query.name
                    );
                    assert!(
                        plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                        "{state} {} must not create an automatic index: {plan:?}",
                        query.name
                    );
                    assert!(
                        plan.iter().all(|detail| {
                            !detail.starts_with("SCAN child ")
                                && !detail.starts_with("SCAN parent ")
                                && !detail.starts_with("SCAN included ")
                                && !detail.starts_with("SCAN host ")
                                && !detail.starts_with("SCAN child_member ")
                                && !detail.starts_with("SCAN host_member ")
                                && !detail.starts_with("SCAN included_member ")
                        }),
                        "{state} {} must not scan Rust summary rows: {plan:?}",
                        query.name
                    );
                }
                if matches!(
                    query.name.as_str(),
                    "rust_macro_input_exists"
                        | "rust_macro_invocation_input"
                        | "rust_macro_invocation_tokens"
                ) {
                    let seek = if query.name == "rust_macro_invocation_tokens" {
                        "SEARCH source_rust_macro_input_tokens USING PRIMARY KEY (blob_id=? AND invocation_occurrence_id=?)"
                    } else {
                        "SEARCH source_rust_macro_inputs USING PRIMARY KEY (blob_id=?)"
                    };
                    assert!(
                        plan.iter().any(|detail| detail.contains(seek)),
                        "{state} {} must seek its source rows by their key: {plan:?}",
                        query.name
                    );
                    assert!(
                        plan.iter().all(|detail| {
                            (!detail.starts_with("SCAN ") || detail == "SCAN CONSTANT ROW")
                                && !detail.contains("AUTOMATIC")
                                && !detail.contains("TEMP B-TREE")
                        }),
                        "{state} {} must not scan macro source rows or create indexes: {plan:?}",
                        query.name
                    );
                }
                if plan.is_empty() {
                    // SQLite emits no QUERY PLAN rows for a VALUES insert
                    // without a lookup. Still require executable VM bytecode
                    // for the exact registered statement and bindings.
                    let mut statement = conn.prepare(&format!("EXPLAIN {}", query.sql)).unwrap();
                    let mut bytecode = statement
                        .query(rusqlite::params_from_iter(query.params.iter()))
                        .unwrap();
                    assert!(
                        bytecode.next().unwrap().is_some(),
                        "pinned query {} has neither a query plan nor bytecode {state}",
                        query.name
                    );
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn go_reverse_qualified_import_seeks_binders_and_package_unit_keys_under_both_statistics_states()
     {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("go_reverse_qualified_import"));
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH binder USING INDEX resolution_go_package_imports_scope")
                        && detail.contains("blob_id=?")
                        && detail.contains("file_scope_key=?")
                }),
                "{state} qualified import binding must seek by caller blob and file Scope: {plan:?}"
            );
            assert!(
                plan.iter().any(|detail| {
                    detail
                        .contains("SEARCH target_package USING INDEX go_package_instances_unit_key")
                        && detail.contains("context_id=? AND unit_key=?")
                }),
                "{state} qualified import target must seek its stored package unit key: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|detail| detail.starts_with("SCAN target_package")),
                "{state} qualified import must not scan the context's packages: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn go_reverse_inventory_seeks_test_variants_and_membership_keys_under_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("go_reverse_inventory_complete"));
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH test_package USING INDEX go_package_instances_for_test")
                        && detail.contains("context_id=? AND for_test=?")
                }),
                "{state} candidate target must seek test variants by their for-test path: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|detail| detail.starts_with("SCAN test_package")),
                "{state} candidate target must not scan the context's packages: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[hardwon("cfb70fbdaf89: the lexical walk read every node of the blob for each candidate site")]
    #[test]
    fn reference_local_path_evidence_seeks_walk_scopes_by_key_under_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("reference_local_path_evidence"));
            assert!(
                plan.iter().any(|detail| {
                    detail == "SEARCH scope USING PRIMARY KEY (blob_id=? AND local_key=?)"
                }),
                "{state} lexical walk must seek each scope node by its key: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|detail| detail == "SEARCH scope USING PRIMARY KEY (blob_id=?)"),
                "{state} lexical walk must not read every node of the blob per site: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn go_binding_receiver_anchor_seeks_declaration_type_under_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("go_point_binding_receiver_anchor"));
            assert!(
                plan.iter().any(|detail| {
                    detail.contains(
                        "SEARCH declaration USING COVERING INDEX source_declarations_name_range",
                    ) && detail.contains("blob_id=? AND name_start_byte=? AND name_end_byte=?")
                }),
                "{state} Go binding anchor must seek the selected declaration range: {plan:?}"
            );
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH bridge USING COVERING INDEX source_native_declaration_bridges_declaration")
                }),
                "{state} Go binding anchor must seek the declaration bridge: {plan:?}"
            );
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH declared USING PRIMARY KEY")
                        && detail.contains("blob_id=? AND definition=?")
                }),
                "{state} Go binding anchor must seek declared type rows: {plan:?}"
            );
            assert!(
                !plan.iter().any(|detail| {
                    detail == "SCAN declaration"
                        || detail == "SCAN bridge"
                        || detail == "SCAN declared"
                }),
                "{state} Go binding anchor must not scan persisted rows: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn go_rename_conflict_queries_use_keyed_bundle_and_summary_seeks_under_both_statistics_states()
    {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().expect("open store");
            let conn = store.conn.lock().expect("store mutex");
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .expect("workspace selection views");
            prepare_pin_context(&conn);
            state.install(&conn);

            let local = explain_pin(&conn, &pinned("go_rename_local_name_conflict"));
            assert!(
                local
                    .iter()
                    .any(|detail| detail.contains("resolution_paths_forward")),
                "{state} local rename collision must seek scope paths: {local:?}"
            );
            assert!(
                local.iter().any(|detail| {
                    detail.contains("SEARCH semantic USING")
                        && detail.contains("blob_id=? AND shared_identity=?")
                }),
                "{state} local rename collision must seek semantic identities: {local:?}"
            );
            assert!(
                !local.iter().any(|detail| {
                    detail == "SEARCH semantic USING PRIMARY KEY (blob_id=?)"
                        || detail == "SCAN semantic"
                }),
                "{state} local rename collision must not scan a blob's semantic catalog: {local:?}"
            );
            let scopes = explain_pin(&conn, &pinned("go_rename_edit_site_scope_keys"));
            assert!(
                scopes.iter().any(|detail| {
                    detail.contains("resolution_paths_forward")
                        && detail.contains("blob_id=?")
                        && detail.contains("start_node=?")
                }),
                "{state} edited-site scope lookup must seek saved paths: {scopes:?}"
            );
            let import = explain_pin(&conn, &pinned("go_rename_import_name_conflict"));
            assert!(
                import
                    .iter()
                    .any(|detail| detail.contains("resolution_go_package_imports_choice")),
                "{state} import rename collision must seek spelling-choice binders: {import:?}"
            );
            assert!(
                import.iter().any(|detail| {
                    detail.contains("SEARCH semantic USING")
                        && detail.contains("blob_id=? AND shared_identity=?")
                }),
                "{state} import rename collision must seek semantic identities: {import:?}"
            );
            assert!(
                import.iter().any(|detail| {
                    detail.contains("SEARCH source_import USING")
                        && detail.contains("source_imports_declaration_range")
                        && detail.contains(
                            "blob_id=? AND declaration_start_byte=? AND declaration_end_byte=?",
                        )
                }),
                "{state} import rename collision must seek the import declaration range: {import:?}"
            );
            let package = explain_pin(&conn, &pinned("go_rename_package_name_conflict"));
            assert!(
                package.iter().any(|detail| {
                    detail.contains("SEARCH export USING PRIMARY KEY")
                        && detail.contains("summary_id=?")
                        && detail.contains("identity_id=?")
                }),
                "{state} package rename collision must seek the summary export key: {package:?}"
            );
            let rebound = explain_pin(&conn, &pinned("go_rename_rebound_root_references"));
            assert!(
                rebound
                    .iter()
                    .any(|detail| detail.contains("resolution_paths_root_terminal")),
                "{state} rebind check must seek root-terminal paths: {rebound:?}"
            );
        }
    }

    #[test]
    fn python_environment_snapshot_inputs_seek_populated_relations_under_both_statistics_states() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.conn.execute(|conn| {
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            for workspace in ["e".repeat(64), "f".repeat(64)] {
                for ordinal in 1..=16 {
                    let oid = format!("{ordinal:040x}");
                    conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,'python',0,?2,?3,?4,1)", rusqlite::params![workspace,format!("pkg{ordinal}/model.py"),oid,"0".repeat(64)]).unwrap();
                    for name in brokk_bifrost_python::declarations::PYTHON_CONFIGURATION_INPUT_NAMES.into_iter().chain(["x_init__.py"]) {
                        conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,input_kind,valid_from) VALUES(?1,'python',0,?2,?3,'configuration',1)", rusqlite::params![workspace,format!("pkg{ordinal}/{name}"),oid]).unwrap();
                    }
                    conn.execute("INSERT OR IGNORE INTO workspace_input_sources VALUES(?1,?2)", rusqlite::params![oid,b"[tool.setuptools.packages.find]\nwhere = ['.']\n".as_slice()]).unwrap();
                }
                let runtime_oid = "f".repeat(40);
                conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,input_kind,valid_from) VALUES(?1,'python',0,'.bifrost/python-runtime-selection.json',?2,'configuration',1)", rusqlite::params![workspace,runtime_oid]).unwrap();
                conn.execute("INSERT OR IGNORE INTO workspace_input_sources VALUES(?1,?2)", rusqlite::params![runtime_oid,br#"{"version":1}"#.as_slice()]).unwrap();
            }
            let query = pinned("python_environment_snapshot_inputs");
            let mut plans = Vec::new();
            for state in PlannerStatisticsState::BOTH {
                state.install(conn);
                let plan = explain_pin(conn, &query);
                eprintln!("{state} {}: {plan:#?}", query.name);
                let mut statement = conn.prepare(&query.sql).unwrap();
                let rows = statement.query_map(rusqlite::params_from_iter(&query.params), |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<Vec<u8>>>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                assert_eq!(rows.len(),64,"{state}: source and configuration partitions must both run: {rows:?}");
                assert_eq!(rows.iter().filter(|(_,kind,bytes)|kind == "configuration" && bytes.is_some()).count(),48,"{state}: selected configuration bytes must be read: {rows:?}");
                assert!(rows.iter().filter(|(_,kind,_)| kind == "configuration").all(|(path,_,_)| brokk_bifrost_python::declarations::PYTHON_CONFIGURATION_INPUT_NAMES.contains(&std::path::Path::new(path).file_name().unwrap().to_str().unwrap())), "{state}: only the shared configuration names may be selected: {rows:?}");
                plans.push((state,plan));
            }
            // Record both plans before checking properties, so a failure shows
            // whether installing corpus statistics changed the access paths.
            for (state,plan) in plans {
                assert!(plan.iter().any(|step| step.starts_with("SEARCH v USING")
                    && step.contains("workspace_id=? AND lang=? AND generation=?")
                    && (step.contains("idx_workspace_file_versions_snapshot_") || step.contains("sqlite_autoindex_workspace_file_versions_"))),
                    "{state} membership must seek its snapshot prefix: {plan:#?}");
                assert!(plan.iter().any(|step| step.starts_with("SEARCH retained USING PRIMARY KEY (content_oid=?)")),
                    "{state} configuration bytes must seek their content primary key: {plan:#?}");
                assert!(plan.iter().all(|step| !step.contains("AUTOMATIC")
                    && !["v", "retained", "workspace_file_versions", "workspace_input_sources"].iter().any(|table| step == &format!("SCAN {table}") || step.starts_with(&format!("SCAN {table} ")))),
                    "{state} snapshot inputs must not scan base tables or build automatic indexes: {plan:#?}");
            }
        });
    }

    #[test]
    fn python_member_operation_readers_seek_populated_source_relations() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.conn.execute(|conn| {
            prepare_pin_context(conn);
            fill_reverse_candidate_fixture(conn);
            conn.execute_batch("UPDATE python_member_operations SET form=1,effect=1,callee_reference=site,receiver_reference=site").unwrap();
            let workspace = "e".repeat(64);
            conn.execute("INSERT INTO workspace_revisions VALUES(?1,'python',0,1)", [&workspace]).unwrap();
            for blob in 1..=16 {
                conn.execute("INSERT INTO python_binding_source VALUES(?1,?2,0,0)",rusqlite::params![blob,super::super::python_binding_rows::NATIVE_SOURCE_FORMAT]).unwrap();
                let path=format!("file{blob}.py");
                let oid = format!("{blob:040x}");
                conn.execute("INSERT INTO blobs(id,blob_oid,lang,generation) VALUES(?1,?2,'python',0)",rusqlite::params![blob,oid]).unwrap();
                conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,'python',0,?2,?3,?4,1)",rusqlite::params![workspace,path,oid,"0".repeat(64)]).unwrap();
                conn.execute("INSERT INTO resolution_binding_slots VALUES(?1,0,0,'known',0)",[blob]).unwrap();
                conn.execute("INSERT INTO python_binding_imports VALUES(?1,0,2,0,1,NULL,jsonb('[\"module\"]'))",[blob]).unwrap();
                conn.execute("INSERT INTO python_binding_export_operations VALUES(?1,0,0,1,jsonb('[\"known\"]'))",[blob]).unwrap();

                conn.execute("INSERT INTO temp.selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) VALUES(?1,?1,'python',?2)",rusqlite::params![blob,path]).unwrap();
                conn.execute("INSERT INTO resolution_unit_summary_members(summary_id,member_ordinal,blob_id,rel_path,source_role) VALUES(1,?1,?1,?2,'source')",rusqlite::params![blob,path]).unwrap();
            }
            let mut environment_plans = Vec::new();
            for state in PlannerStatisticsState::BOTH {
                state.install(conn);
                let query = pinned("python_environment_source_rows");
                let plan = explain_pin(conn, &query);
                eprintln!("{state} {}: {plan:#?}", query.name);
                let mut statement = conn.prepare(&query.sql).unwrap();
                let rows = statement.query_map(rusqlite::params_from_iter(query.params.iter()), |_| Ok(())).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                assert_eq!(rows.len(), 96, "{state}: every child arm must run for all 16 selected files");
                environment_plans.push((state, plan));
                conn.execute_batch("UPDATE python_binding_source SET export_curated=1,export_wildcard=1; DELETE FROM temp.py_env_route_inputs; DELETE FROM temp.py_env_routes; DELETE FROM temp.py_env_names; DELETE FROM temp.py_env_surfaces; DELETE FROM temp.py_env_segments; DELETE FROM temp.py_env_imports; DELETE FROM temp.py_env_candidates; DELETE FROM temp.py_env_roots; DELETE FROM temp.py_env_files;").unwrap();
                for name in ["python_env_select_files","python_env_stage_files","python_env_stage_roots","python_env_stage_candidates","python_env_stage_imports","python_env_stage_segments","python_env_stage_surfaces","python_env_stage_module_names","python_env_stage_curated_names","python_env_stage_wildcard_names","python_env_select_route_inputs","python_env_stage_route_inputs","python_env_stage_routes","python_env_stage_unplaced_routes"] {
                    let query = pinned(name);
                    let plan = explain_pin(conn, &query);
                    eprintln!("{state} {name}: {plan:#?}");
                    assert!(plan.iter().all(|step| !step.contains("AUTOMATIC") && !["f", "b", "s", "i", "slots", "e", "op", "reset", "providers", "roots", "segments", "target", "provider", "imports", "names"].iter().any(|alias| {
                        // f/slots are selected TEMP inputs in fact staging. Only
                        // persistent tables must always be sought by their keys.
                        let base_alias = match *alias {
                            "f" => matches!(name, "python_env_select_files" | "python_env_stage_files" | "python_env_stage_curated_names"),
                            "imports" => name == "python_env_stage_routes",
                            _ => true,
                        };
                        base_alias && (step == &format!("SCAN {alias}") || step.starts_with(&format!("SCAN {alias} ")))
                    })), "{state} {name}: populated persistent facts must be sought: {plan:#?}");
                    let mut statement = conn.prepare(&query.sql).unwrap();
                    statement.reset_status(rusqlite::StatementStatus::RePrepare);
                    let mut rows = statement.query(rusqlite::params_from_iter(&query.params)).unwrap();
                    while rows.next().unwrap().is_some() {}
                    drop(rows);
                    // These run once on the writer, outside the retained-reader
                    // QPSG scope. STAT4 may reprepare once at the initial snapshot
                    // bind; no statement is rebound for individual source rows.
                    let reprepares = statement.get_status(rusqlite::StatementStatus::RePrepare);
                    eprintln!("{state} {name}: reprepares={reprepares}");
                    let maximum = i32::from(matches!(name, "python_env_select_files" | "python_env_stage_files"));
                    assert!(reprepares <= maximum, "{state} {name}: per-set initial binding, never per-row reprepare: {reprepares}");
                }
                // The one-row pins above also seed the following relational
                // pins. Exercise both larger row_batch shapes without changing
                // that fixture, including typed BLOB provider digests.
                for (name, prefix, row_sql) in [
                    ("python_env_stage_roots", super::super::python_unit_summaries::stage_roots_prefix(), super::super::python_unit_summaries::STAGE_ROOT_ROW),
                    ("python_env_stage_candidates", super::super::python_unit_summaries::stage_candidates_prefix(), super::super::python_unit_summaries::STAGE_CANDIDATE_ROW),
                    ("python_env_stage_route_inputs", super::super::python_unit_summaries::stage_route_inputs_prefix(), super::super::python_unit_summaries::STAGE_ROUTE_INPUT_ROW),
                ] {
                    let query = pinned(name);
                    for width in [8, 64] {
                        conn.execute_batch("SAVEPOINT python_environment_batch_pin").unwrap();
                        let sql = format!("{prefix} {}", vec![row_sql; width].join(", "));
                        let values = (0..width).flat_map(|index| {
                            let mut values = query.params.clone();
                            if name == "python_env_stage_route_inputs" {
                                // The fixture's single context occupies site 0.
                                values[1] = rusqlite::types::Value::Integer(index as i64 + 1);
                            }
                            values
                        }).collect::<Vec<_>>();
                        let mut statement = conn.prepare(&sql).unwrap();
                        statement.reset_status(rusqlite::StatementStatus::RePrepare);
                        statement.execute(rusqlite::params_from_iter(&values)).unwrap();
                        assert!(statement.get_status(rusqlite::StatementStatus::VmStep) > 0);
                        let reprepares = statement.get_status(rusqlite::StatementStatus::RePrepare);
                        assert_eq!(reprepares, 0, "{state} {name} rows={width}");
                        eprintln!("{state} {name}: rows={width} reprepares={reprepares}");
                        drop(statement);
                        conn.execute_batch("ROLLBACK TO python_environment_batch_pin; RELEASE python_environment_batch_pin").unwrap();
                    }
                }
                assert_eq!(conn.query_row("SELECT count(*) FROM temp.py_env_files", [], |r| r.get::<_,i64>(0)).unwrap(), 16);
                assert_eq!(conn.query_row("SELECT count(*) FROM temp.py_env_imports", [], |r| r.get::<_,i64>(0)).unwrap(), 16);
                assert_eq!(conn.query_row("SELECT count(*) FROM temp.py_env_routes", [], |r| r.get::<_,i64>(0)).unwrap(), 16);
                assert_eq!(conn.query_row("SELECT count(*) FROM temp.py_env_names WHERE surface='curated'", [], |r| r.get::<_,i64>(0)).unwrap(), 16);

                // Restore the shared source fixture before the member-operation
                // pins and the next statistics state read its original policies.
                conn.execute_batch("UPDATE python_binding_source SET export_curated=0,export_wildcard=0").unwrap();

                for (name,index) in [("python_member_operations_inventory","python_member_operations_inventory"),("python_member_operation_names_lookup","python_member_operation_names_spelling")] {
                    let plan=explain_pin(conn,&pinned(name));
                    assert!(plan.iter().any(|line| line.contains("SEARCH") && line.contains(index)),"{state} {name}: {plan:?}");
                    assert!(plan.iter().all(|line|!line.contains("SCAN ") && !line.contains("AUTOMATIC") && !line.contains("TEMP B-TREE")),"{state} {name}: {plan:?}");
                }
                for (name,index,rows) in [
                    ("python_owner_member_operations","python_member_operation_names_spelling",2752),
                    ("python_late_member_operations","python_member_operations_inventory",2752),
                    ("python_direct_member_writes","resolution_identities_spelling",0),
                ] {
                    let mut query=pinned(name);
                    query.params[0]=rusqlite::types::Value::Integer(super::super::python_binding_rows::NATIVE_SOURCE_FORMAT);
                    query.params[1]=rusqlite::types::Value::Text("name42".into());
                    let plan=explain_pin(conn,&query);
                    assert!(plan.iter().any(|line|line.contains("SEARCH") && line.contains(index)),"{state} {name}: {plan:?}");
                    assert!(plan.iter().all(|line|!line.contains("AUTOMATIC") && !line.starts_with("SCAN op ") && !line.starts_with("SCAN names ")),"{state} {name}: {plan:?}");
                    let mut statement=conn.prepare(&query.sql).unwrap();
                    let observed=statement.query_map(rusqlite::params_from_iter(query.params.iter()),|row|Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                    assert_eq!(observed.len(),rows,"{state} {name}");
                    eprintln!("M4-5 SQL state={state} name={name} source-operations=4096 rows={} vm-steps={} fullscan-steps={} plan={plan:?}",observed.len(),statement.get_status(rusqlite::StatementStatus::VmStep),statement.get_status(rusqlite::StatementStatus::FullscanStep));
                }
            }
            // Capture and execute both states before reporting any seek failure.
            for (state, plan) in environment_plans {
                assert!(plan.iter().any(|step| step.starts_with("SEARCH f USING") && step.contains("workspace_id=? AND lang=? AND generation=? AND input_kind=?")), "{state} snapshot membership must seek its workspace/language/generation/kind prefix: {plan:#?}");
                assert!(plan.iter().any(|step| step.starts_with("SEARCH b USING") && step.contains("blob_oid=?")), "{state} selected blobs must seek by oid: {plan:#?}");
                assert!(plan.iter().any(|step| step.starts_with("SEARCH s USING INTEGER PRIMARY KEY")), "{state} source marker must seek its blob key: {plan:#?}");
                for (alias, arms) in [("slots",2),("i",2),("e",1),("o",2)] {
                    let probes = plan.iter().filter(|step| step.starts_with(&format!("SEARCH {alias} "))).collect::<Vec<_>>();
                    assert!(probes.len() >= arms && probes.iter().all(|step| step.contains("(blob_id=?")), "{state} every {alias} arm must seek its leading blob key: {plan:#?}");
                }
                // Scans of materialized selected/inputs and json_each are bounded query inputs.
                // Exclude TEMP B-TREE: ORDER BY over the UNION ALL legitimately sorts.
                assert!(plan.iter().all(|step| !step.contains("AUTOMATIC") && !["f","b","i","o","slots","e","workspace_file_versions","blobs"].iter().any(|alias| step == &format!("SCAN {alias}") || step.starts_with(&format!("SCAN {alias} "))) && !step.starts_with("SCAN python_binding_")), "{state} retained source reads must not scan base tables or build automatic indexes: {plan:#?}");
            }
        });
    }

    #[test]
    #[hardwon("#5671: empty boundary gap buckets scanned every scope mount and lookup")]
    fn boundary_gap_buckets_are_sought_before_populated_mount_scopes() {
        use rusqlite::{StatementStatus, params, params_from_iter};

        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            store
                .select_writer_workspace_snapshots(&conn, &HashMap::default())
                .unwrap();
            prepare_pin_context(&conn);
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            let query = pinned("selected_boundary_candidate_gap_branches");
            let mut empty_steps = None;
            for size in [1_i64, 256] {
                for id in 1..=size {
                    conn.execute("INSERT OR IGNORE INTO temp.selected_resolution_mounts(mount_ordinal,blob_id) VALUES(?1,?1)", [id]).unwrap();
                    conn.execute(
                        "INSERT OR IGNORE INTO temp.selected_resolution_scope_mounts VALUES(?1)",
                        [id],
                    )
                    .unwrap();
                    conn.execute("INSERT OR IGNORE INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES(?1,6,-1,7,?1,?1)", [id]).unwrap();
                }
                state.install(&conn);
                let plan = explain_pin(&conn, &query);
                let bucket = plan.iter().position(|row| row.contains("SEARCH available USING COVERING INDEX resolution_gaps_root_branches (covers=?)")).unwrap_or_else(|| panic!("{state}: {plan:?}"));
                let scope = plan.iter().position(|row| row == "SCAN scope").unwrap();
                assert!(bucket < scope, "{state}: bucket must lead scope: {plan:?}");
                let mut statement = conn.prepare(&query.sql).unwrap();
                assert!(
                    statement
                        .query(params_from_iter(&query.params))
                        .unwrap()
                        .next()
                        .unwrap()
                        .is_none()
                );
                let steps = statement.get_status(StatementStatus::VmStep);
                if let Some(previous) = empty_steps {
                    assert_eq!(
                        steps, previous,
                        "{state}: empty bucket work must not grow with scope: {plan:?}"
                    );
                }
                empty_steps = Some(steps);
            }
            // Nonempty buckets still honor exact lookups and the selected scope.
            // Blob 999 is not mounted; lookup 8 is not requested.
            for (blob, lookup, reason) in [(1, 0, 1001), (2, 7, 1002), (3, 8, 1003), (999, 7, 1004)]
            {
                conn.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES(?1,5,-1,?2,?3,?3)",params![blob,lookup,reason]).unwrap();
            }
            state.install(&conn);
            let rows = conn
                .prepare(&query.sql)
                .unwrap()
                .query_map(params_from_iter(&query.params), |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(rows, [(1, 0, 1001), (2, 7, 1002)]);
        }
    }

    #[test]
    #[hardwon("#5671: file-keyed Go participation and caller roles scanned context package files")]
    fn go_file_keyed_readers_seek_versions_before_package_files() {
        let store = AnalyzerStore::open_ephemeral().expect("open Go planner store");
        let conn = store.conn.lock().expect("store mutex");
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .unwrap();
        prepare_pin_context(&conn);
        // Access-plan fixture: publication FK setup is irrelevant to these seeks.
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        for id in 1..=256_i64 {
            let path = format!("pkg/{id}/main.go");
            conn.execute("INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,?2,'go',1,?3,?4,?5,1)", rusqlite::params![id, "a".repeat(64), path, "b".repeat(40), "c".repeat(64)]).unwrap();
            conn.execute("INSERT INTO go_package_instances(package_id,context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key) VALUES(?1,1,?2,'main','',?2,?3,1,jsonb('[]'),?3)",rusqlite::params![id,path,[1_u8;32]]).unwrap();
            conn.execute(
                "INSERT INTO go_package_files VALUES(?1,'go',?2)",
                rusqlite::params![id, path],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO go_context_publications VALUES(1,1,?1,'go',1,1,NULL,?2,?2,1,jsonb('[]'))",
            rusqlite::params!["a".repeat(64), [1_u8; 32]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO temp.selected_workspace_revisions VALUES(?1,'go',1,1)",
            ["a".repeat(64)],
        )
        .unwrap();
        conn.execute("INSERT INTO temp.selected_resolution_mounts(mount_ordinal,file_version_id,semantic_language) VALUES(0,1,'go')",[]).unwrap();
        conn.execute(
            "INSERT INTO go_package_files VALUES(1,'ignored','pkg/1/main.go')",
            [],
        )
        .unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for name in [
                "go_domain_deferred_member_participation",
                "go_interval_resolution_operation_go_named_caller_source_role",
            ] {
                let query = pinned(name);
                let plan = explain_pin(&conn, &query);
                let version = plan
                    .iter()
                    .position(|line| line.starts_with("SEARCH versions USING INTEGER PRIMARY KEY"))
                    .unwrap_or_else(|| {
                        panic!("{state} {name}: version primary-key seek: {plan:?}")
                    });
                let membership = plan
                    .iter()
                    .position(|line| {
                        line.starts_with("SEARCH source USING")
                            && line.contains("idx_go_package_files_file_role")
                            && line.contains("rel_path=?")
                    })
                    .unwrap_or_else(|| {
                        panic!("{state} {name}: path-keyed membership seek: {plan:?}")
                    });
                assert!(
                    version < membership,
                    "{state} {name}: version must lead membership: {plan:?}"
                );
                assert!(
                    !plan.iter().any(|line| line.starts_with("SCAN source")
                        || line.starts_with("SCAN package")
                        || (line.contains("AUTOMATIC")
                            && (line.contains(" source ")
                                || line.contains(" package ")
                                || line.contains(" versions ")))),
                    "{state} {name}: no context-wide membership scans: {plan:?}"
                );
                let rows = conn
                    .prepare(&query.sql)
                    .unwrap()
                    .query_map(rusqlite::params_from_iter(query.params.iter()), |_| Ok(()))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let expected = if name == "go_domain_deferred_member_participation" {
                    // The shared reader now returns both participating and ignored roles.
                    2
                } else {
                    1
                };
                assert_eq!(
                    rows.len(),
                    expected,
                    "{state} {name}: fixture probe must execute"
                );
            }
        }
    }

    #[test]
    fn go_package_member_sources_seek_selected_variants() {
        let store = AnalyzerStore::open_ephemeral().expect("Go member planner store");
        let conn = store.conn.lock().expect("store mutex");
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .unwrap();
        prepare_pin_context(&conn);
        // A path-keyed source probe must stay selective among other packages.
        // The same production file also belongs to an internal test variant.
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        for id in 1..=256_i64 {
            let path = format!("pkg/{id}/main.go");
            conn.execute("INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,?2,'go',1,?3,?4,?5,1)", rusqlite::params![id, "a".repeat(64), path, "b".repeat(40), "c".repeat(64)]).unwrap();
            conn.execute("INSERT INTO go_package_instances(package_id,context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key) VALUES(?1,1,?2,'main','',?2,?3,1,jsonb('[]'),?3)", rusqlite::params![id,path,[1_u8;32]]).unwrap();
            conn.execute(
                "INSERT INTO go_package_files VALUES(?1,'go',?2)",
                rusqlite::params![id, path],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO go_context_publications VALUES(1,1,?1,'go',1,1,NULL,?2,?2,1,jsonb('[]'))",
            rusqlite::params!["a".repeat(64), [1_u8; 32]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO temp.selected_workspace_revisions VALUES(?1,'go',1,1)",
            ["a".repeat(64)],
        )
        .unwrap();
        conn.execute("INSERT INTO temp.selected_resolution_mounts(mount_ordinal,file_version_id,semantic_language) VALUES(0,1,'go')", []).unwrap();
        conn.execute("INSERT INTO go_package_instances(package_id,context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key) VALUES(257,1,'pkg/1 [pkg/1.test]','main','pkg/1','pkg/1',?1,1,jsonb('[]'),?1)", [[1_u8;32]]).unwrap();
        conn.execute("INSERT INTO go_package_files VALUES(257,'go','pkg/1/main.go'),(257,'test','pkg/1/other_test.go')", []).unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let query = pinned("go_domain_package_member_sources");
            let plan = explain_pin(&conn, &query);
            eprintln!("{state} selected variant: {plan:?}");
            let membership = pinned("go_domain_caller_context_publishes_file");
            let membership_plan = explain_pin(&conn, &membership);
            eprintln!("{state} caller context membership: {membership_plan:?}");
            assert!(
                membership_plan.iter().any(|line| line
                    .contains("SEARCH source USING COVERING INDEX idx_go_package_files_file_role")
                    && line.contains("rel_path=?")),
                "{state}: {membership_plan:?}"
            );
            assert!(
                membership_plan.iter().any(|line| {
                    line.starts_with("SEARCH package USING")
                        && !line.contains("AUTOMATIC")
                        && (line.contains("INTEGER PRIMARY KEY")
                            || line.contains("context_id=? AND package_id=?"))
                }),
                "{state}: {membership_plan:?}"
            );

            let rows = conn
                .prepare(&query.sql)
                .unwrap()
                .query_map(rusqlite::params_from_iter(query.params.iter()), |row| {
                    row.get::<_, Option<i64>>(0)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![Some(0)],
                "{state}: only the active production variant"
            );

            assert!(
                plan.iter()
                    .any(|line| line.contains("SEARCH package USING INTEGER PRIMARY KEY")),
                "{state}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|line| line.contains("SEARCH member USING")
                        && line.contains("package_id=?")),
                "{state}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|line| line.contains("SEARCH active USING")
                        && line.contains("package_id=?")),
                "{state}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| (line.contains("AUTOMATIC")
                    && (line.contains(" member ")
                        || line.contains(" package ")
                        || line.contains(" active ")))
                    || line.starts_with("SCAN member")
                    || line.starts_with("SCAN package")
                    || line.starts_with("SCAN active")),
                "{state}: {plan:?}"
            );
        }
    }

    #[test]
    fn go_interval_readers_join_selected_versions_with_indexes() {
        let store = AnalyzerStore::open_ephemeral().expect("open Go planner store");
        let conn = store.conn.lock().expect("store mutex");
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .expect("selected revisions");
        prepare_pin_context(&conn);
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for query in pinned_queries().into_iter().filter(|query| {
                query.name.starts_with("go_interval_") || query.name.starts_with("go_domain_")
            }) {
                let plan = explain_pin(&conn, &query);
                assert!(
                    !plan
                        .iter()
                        .any(|line| line.starts_with("SCAN versions")
                            || line.starts_with("SCAN file ")),
                    "{state} {} must seek selected file versions: {plan:?}",
                    query.name
                );
                assert!(
                    !plan.iter().any(|line| line.contains("AUTOMATIC")
                        && [
                            " versions ",
                            " file ",
                            " path_members ",
                            " publications ",
                            " packages "
                        ]
                        .iter()
                        .any(|alias| line.contains(alias))),
                    "{state} {} must use declared indexes for persisted path membership: {plan:?}",
                    query.name
                );
            }
        }
    }

    #[cfg(test)]
    /// No production statement opens a resolution table outside tier 1.
    ///
    /// Tier 2 is computed on demand, so a statement that reads one of its
    /// families is reading rows the writer no longer produces. The check is
    /// structural: SQLite's own bytecode names every b-tree a statement
    /// opens through its root page, and `sqlite_schema` maps that root page
    /// back to a table. No source text is scanned, so a statement assembled
    /// at runtime is covered exactly as a literal one is.
    #[hardwon("#6218: TEMP root pages were mistaken for unrelated main-schema tables")]
    #[test]
    fn no_pinned_statement_opens_a_resolution_table_outside_tier_one() {
        let store = AnalyzerStore::open_ephemeral().expect("open store");
        let conn = store.conn.lock().expect("store mutex");
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .expect("workspace selection views");
        prepare_pin_context(&conn);
        let mut opened_any = false;
        let mut opened_compilation_symbols = false;
        for query in pinned_queries() {
            let mut statement = conn
                .prepare(&format!("EXPLAIN {}", query.sql))
                .unwrap_or_else(|error| {
                    panic!("pinned query {} does not prepare: {error}", query.name)
                });
            let roots = statement
                .query_map(rusqlite::params_from_iter(query.params.iter()), |row| {
                    Ok((
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .expect("explain pinned query bytecode")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect pinned query bytecode")
                .into_iter()
                // P3 selects the database: main is 0, TEMP is 1. Root pages
                // are only unique within that database; TEMP inputs are not
                // persisted tier-one families.
                .filter(|(opcode, _, database)| opcode == "OpenRead" && *database == 0)
                .map(|(_, root, _)| root)
                .collect::<std::collections::BTreeSet<_>>();
            drop(statement);
            for root in roots {
                let table = conn
                    .query_row(
                        "SELECT COALESCE(tbl_name, name) FROM sqlite_schema WHERE rootpage = ?1",
                        [root],
                        |row| row.get::<_, String>(0),
                    )
                    .ok();
                let Some(table) = table else { continue };
                if table == "csharp_compilation_symbols" {
                    opened_compilation_symbols = true;
                    let columns = conn.prepare("SELECT name FROM pragma_table_info('csharp_compilation_symbols') ORDER BY cid").unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                    assert_eq!(columns, ["compilation_id", "symbol", "source"]);
                    continue;
                }
                if !table.starts_with("resolution_")
                    && !table.starts_with("python_member_operation")
                {
                    continue;
                }
                opened_any = true;
                assert!(
                    super::super::resolution::PERSISTED_RESOLUTION_TABLES.contains(&table.as_str())
                        || matches!(
                            table.as_str(),
                            "python_member_operations" | "python_member_operation_names"
                        ),
                    "pinned query {} opens {table}, which tier 1 does not persist",
                    query.name
                );
            }
        }
        assert!(
            opened_compilation_symbols,
            "the pinned configuration projection must actually read symbol rows"
        );
        assert!(
            opened_any,
            "the registry must contain at least one resolution reader for this pin to mean anything"
        );
    }

    #[cfg(test)]
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

    #[cfg(test)]
    /// A no-op rebuild and modest blob growth keep the previous statistics.
    #[test]
    #[hardwon("#6458: each new scoped-build blob triggered a full-store ANALYZE")]
    fn the_stale_check_tolerates_modest_blob_growth() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        {
            let conn = store.conn.lock().expect("store mutex");
            insert_one_declaration(&conn);
            conn.execute_batch(
                "WITH RECURSIVE inputs(n) AS (
                   VALUES(2) UNION ALL SELECT n + 1 FROM inputs WHERE n < 100
                 ) INSERT INTO blobs(blob_oid, lang)
                   SELECT printf('%040d', n), 'rust' FROM inputs;",
            )
            .unwrap();
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
                .is_none(),
            "one new file must not re-analyze every table"
        );
        assert!(
            store
                .refresh_planner_statistics_if_stale()
                .unwrap()
                .is_none(),
            "and must then settle again"
        );
    }

    #[cfg(test)]
    /// A pinned query whose plan the captured corpus statistics change, so a
    /// test can see which statistics a connection is planning with.
    ///
    /// The path-symbol lookups are the two pins that moved on all thirty-six
    /// corpus stores (issue #3016's corpus report), which is why one of them is
    /// the subject here.
    const STATISTICS_SENSITIVE_PIN: &str = "exact_path_symbol_fqn";

    #[cfg(test)]
    /// A refresh makes this store's own pooled readers plan again (issue
    /// #3029).
    ///
    /// The middle assertion is the defect this test exists for: a reader that
    /// has already answered a query keeps the statistics it loaded, so without
    /// the recycle the new plan appears only when the whole store is reopened.
    /// The first refresh here is what makes the second one representative of
    /// the collection hook rather than of the build hook: creating
    /// `sqlite_stat1` is a schema change every connection notices, and
    /// rewriting its rows is not.
    #[test]
    #[hardwon("d78f9a16030c: pooled readers retained statements prepared under old statistics")]
    fn a_refresh_makes_a_pooled_reader_plan_with_the_new_statistics() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        {
            let conn = store.conn.lock().expect("store mutex");
            insert_one_declaration(&conn);
        }
        store.refresh_planner_statistics().unwrap();
        let pin = pinned(STATISTICS_SENSITIVE_PIN);

        let planned_without = {
            let conn = store.read_conn().expect("pooled reader");
            explain_pin(&conn, &pin)
        };
        assert_eq!(
            store.readers.idle_len(),
            1,
            "the reader must be back in the pool, checked in with the plans it just made"
        );

        // Rewrite the statistics the way a collection's refresh does, without
        // telling the pool.
        store
            .conn
            .execute(|conn| with_representative_statistics(conn));
        let planned_by_the_stale_reader = {
            let conn = store.read_conn().expect("pooled reader");
            explain_pin(&conn, &pin)
        };
        assert_eq!(
            planned_by_the_stale_reader, planned_without,
            "a checked-in reader keeps the statistics it loaded, which is what the recycle is for"
        );

        assert_eq!(
            store.recycle_readers_for_new_statistics(),
            1,
            "the recycle must close the one idle reader"
        );
        let planned_with = {
            let conn = store.read_conn().expect("pooled reader");
            explain_pin(&conn, &pin)
        };
        assert_ne!(
            planned_with, planned_without,
            "after the recycle the pool must hand back a reader that planned with the new statistics"
        );
    }

    #[cfg(test)]
    /// A reader that was out while the statistics changed is closed when it
    /// comes back rather than returned to the idle set.
    ///
    /// This is the half a bare "drop the idle readers" recycle would miss: the
    /// reader checked out across the refresh is exactly the one a busy server
    /// has, and reusing it would keep the old plans indefinitely.
    #[test]
    #[hardwon("d78f9a16030c: a reader checked out during refresh could re-enter the stale pool")]
    fn a_reader_checked_out_across_a_refresh_is_not_returned_to_the_pool() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        {
            let conn = store.conn.lock().expect("store mutex");
            insert_one_declaration(&conn);
        }
        store.refresh_planner_statistics().unwrap();

        let reader = store.read_conn().expect("pooled reader");
        assert_eq!(store.readers.idle_len(), 0);
        assert_eq!(
            store.recycle_readers_for_new_statistics(),
            0,
            "there is no idle reader to close while this one is out"
        );
        drop(reader);
        assert_eq!(
            store.readers.idle_len(),
            0,
            "the reader that was out across the refresh must be closed on checkin"
        );

        let reader = store.read_conn().expect("pooled reader");
        drop(reader);
        assert_eq!(
            store.readers.idle_len(),
            1,
            "and the connection opened after the refresh must be kept"
        );
    }

    #[cfg(test)]
    /// A store that holds blobs but no statistics gets them when it is opened
    /// (issue #3031), and a store whose statistics are current does not pay for
    /// the check twice.
    ///
    /// The repair is counted rather than timed: `ANALYZE` on a one-blob store
    /// is too fast to distinguish from the open around it.
    #[test]
    #[hardwon("d78f9a16030c: opening a populated store without sqlite_stat1 left a latency cliff")]
    fn opening_a_built_store_without_statistics_repairs_them_once() {
        let _guard = statistics_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("cache.db");
        {
            let store = AnalyzerStore::open_persistent(&db_path).unwrap();
            store.conn.execute(|conn| insert_one_declaration(conn));
            assert_eq!(
                store.planner_statistics_rows().unwrap(),
                0,
                "this is the state a build under BIFROST_STORE_STATISTICS=off leaves behind"
            );
        }

        let repairs = planner_statistics_repairs();
        {
            let store = AnalyzerStore::open_persistent(&db_path).unwrap();
            assert_eq!(
                planner_statistics_repairs(),
                repairs + 1,
                "opening a built store with no statistics must analyze it"
            );
            assert!(
                store.planner_statistics_rows().unwrap() > 0,
                "and must leave real statistics behind"
            );
        }

        let repairs = planner_statistics_repairs();
        drop(AnalyzerStore::open_persistent(&db_path).unwrap());
        assert_eq!(
            planner_statistics_repairs(),
            repairs,
            "a store whose statistics still describe it must not be analyzed again"
        );
    }

    #[cfg(test)]
    /// An empty store is not analyzed on open.
    ///
    /// `ANALYZE` writes no row for an empty table, so a store with nothing in
    /// it would read as stale at every open and pay for a refresh that can
    /// produce nothing. Every ephemeral workspace opens exactly such a store.
    #[test]
    #[hardwon("d78f9a16030c: empty-store open must avoid an unnecessary statistics pass")]
    fn opening_an_empty_store_does_not_analyze_it() {
        let _guard = statistics_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let repairs = planner_statistics_repairs();
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        assert_eq!(
            planner_statistics_repairs(),
            repairs,
            "an empty database has no cardinalities to describe"
        );
        assert_eq!(store.planner_statistics_rows().unwrap(), 0);
    }

    #[cfg(test)]
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

#[cfg(test)]
mod native_tests {
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::Connection;

    use super::super::ReaderPool;

    #[cfg(test)]
    #[test]
    #[hardwon("#3029: readers checked out across statistics refresh could re-enter the stale pool")]
    fn statistics_refresh_retires_idle_and_checked_out_readers() {
        use super::super::SelectedReader;

        let pool = ReaderPool::new(None);
        let open = |statistics_epoch| SelectedReader {
            conn: Connection::open_in_memory().unwrap(),
            selection: None,
            resolution_selection: None,
            statistics_epoch,
            query_planner_stability_before_resolution: None,
        };
        let (old_epoch, empty) = pool.acquire();
        assert!(empty.is_none());
        let (second_epoch, empty) = pool.acquire();
        assert!(empty.is_none());
        let (opening_epoch, empty) = pool.acquire();
        assert!(empty.is_none());
        pool.checkin(open(old_epoch));
        pool.checkin(open(second_epoch));
        let (_, borrowed) = pool.acquire();
        assert_eq!(pool.recycle(), 1);
        assert_eq!(pool.idle_len(), 0);
        pool.checkin(borrowed.unwrap());
        assert_eq!(pool.idle_len(), 0);
        // An open racing the refresh keeps its old stamp and releases its permit.
        pool.checkin(open(opening_epoch));
        assert_eq!(pool.idle_len(), 0);
        let (new_epoch, empty) = pool.acquire();
        assert!(empty.is_none());
        assert_ne!(old_epoch, new_epoch);
        pool.checkin(open(new_epoch));
        assert_eq!(pool.idle_len(), 1);
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#3029: active and streaming reader pools retained plans from old statistics")]
    fn refresh_recycles_all_store_reader_classes_and_populates_statistics() {
        let store = super::AnalyzerStore::open_ephemeral().unwrap();
        store.conn.execute(|conn| {
            conn.execute_batch(
                "CREATE TABLE planner_fixture(k INTEGER PRIMARY KEY, value INTEGER NOT NULL);
                 CREATE INDEX planner_fixture_value ON planner_fixture(value);
                 WITH RECURSIVE inputs(k) AS (
                   VALUES(1) UNION ALL SELECT k + 1 FROM inputs WHERE k < 2000
                 ) INSERT INTO planner_fixture SELECT k, k % 3 FROM inputs;",
            )
            .unwrap();
        });
        for pool in [
            &store.readers,
            &store.active_readers,
            &store.streaming_readers,
        ] {
            let reader = store
                .read_conn_from_pool(pool, crate::cache_db::open_readonly_temp_connection)
                .unwrap();
            let count: i64 = reader
                .query_row("SELECT count(*) FROM planner_fixture", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 2000);
            drop(reader);
            assert_eq!(pool.idle_len(), 1);
        }
        let borrowed = store.read_conn().unwrap();
        assert!(store.refresh_planner_statistics().unwrap().stat1_rows > 0);
        drop(borrowed);
        for pool in [
            &store.readers,
            &store.active_readers,
            &store.streaming_readers,
        ] {
            assert_eq!(pool.idle_len(), 0);
        }
        let reader = store.read_conn().unwrap();
        let plan: String = reader
            .query_row(
                "EXPLAIN QUERY PLAN SELECT k FROM planner_fixture WHERE value = ?1",
                [1],
                |row| row.get(3),
            )
            .unwrap();
        assert!(plan.contains("planner_fixture_value"), "{plan}");
        drop(reader);
        store.conn.execute(|conn| {
            conn.execute(
                "UPDATE sqlite_stat1 SET stat = '9000 3000' WHERE idx = 'planner_fixture_value'",
                [],
            )
            .unwrap();
        });
        store.reload_planner_statistics().unwrap();
        assert_eq!(store.readers.idle_len(), 0);
        let retained: String = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT stat FROM sqlite_stat1 WHERE idx = 'planner_fixture_value'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, "9000 3000", "reload must not resample statistics");
    }
}

#[cfg(test)]
mod rust_crate_row_plans {
    use super::pinned_plans::{explain_pin, pinned};
    use crate::analyzer::store::AnalyzerStore;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    #[cfg(test)]
    #[test]
    fn rust_crate_reverse_and_selected_queries_use_indexes() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute_batch(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'rust', 0);
             INSERT INTO rust_crate_topologies VALUES(1, zeroblob(32), zeroblob(32),
                 'test', 'lib', 'sample', '2021', 'std', jsonb('[\"test\"]'), 1, zeroblob(32), 'complete');
             INSERT INTO rust_crate_containers VALUES(1, 'crate', 'module', 'root');
             INSERT INTO rust_crate_container_members SELECT 1, 'crate', id FROM blobs;
             INSERT INTO rust_crate_container_sources SELECT 1, 'crate', id, 0, 'src/lib.rs', 'declared', NULL, NULL FROM blobs;
             INSERT INTO rust_crate_exports(topology_id, module_path, namespace, name,
                 origin, visibility, restricted_module_path, declaration_blob_id,
                 declaration_site, target_crate_key, target_module_path, target_name)
             SELECT 1, 'crate', 'type', 'X', 'declaration',
                 'public', NULL, id, 0, zeroblob(32), 'crate', 'X' FROM blobs;
             INSERT INTO rust_crate_imports VALUES(1, 'crate', 'type', 'X', 1, 0, 0,
                 zeroblob(32), 'crate', 'X');
             INSERT INTO rust_crate_reexport_routes VALUES(1, 'crate', 'X', zeroblob(32),
                 'crate', 'X', 'public', NULL);
             INSERT INTO rust_crate_glob_reexport_routes VALUES(1, 'crate', zeroblob(32), 'crate', 'public', NULL);",
        ).unwrap();
        conn.execute_batch(
            "INSERT INTO workspace_revisions VALUES(printf('%064d', 0), 'rust', 0, 1);
             INSERT INTO workspace_file_versions(workspace_id, lang, generation, rel_path,
                 blob_oid, projection_digest, valid_from)
             VALUES(printf('%064d', 0), 'rust', 0, 'src/lib.rs',
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', printf('%064d', 0), 1);
             INSERT INTO rust_crate_versions VALUES(printf('%064d', 0), 'rust', 0,
                 zeroblob(32), 1, NULL, NULL, 1);
             INSERT INTO selected_workspace_revisions VALUES(printf('%064d', 0), 'rust', 0, 1);",
        )
        .unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (name, index) in [
                ("rust_crate_imports_target", "rust_crate_imports_target"),
                (
                    "rust_crate_glob_reexport_routes_target",
                    "rust_crate_glob_reexport_routes_target",
                ),
                ("rust_crate_imports_binder", "blob_id=? AND binder_scope=?"),
                (
                    "rust_crate_exports_declaration",
                    "rust_crate_exports_declaration",
                ),
                (
                    "rust_crate_reexport_routes_target",
                    "rust_crate_reexport_routes_target",
                ),
                ("selected_rust_crates", "rust_crate_topologies_crate_key"),
                (
                    "selected_rust_crate_containers",
                    "SEARCH modules USING PRIMARY KEY",
                ),
                (
                    "rust_crate_exports_reachable",
                    "rust_crate_reexport_routes_target",
                ),
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                assert!(
                    plan.iter().any(|row| row.contains(index)),
                    "{state:?} {name}: {plan:?}"
                );
                assert!(
                    !plan.iter().any(|row| row.contains("AUTOMATIC")),
                    "{state:?} {name}: {plan:?}"
                );
            }
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_tests_test_support {

    /// Serializes the tests that set `BIFROST_STORE_STATISTICS`, which is
    /// process-wide state, with any other test that observes the switch while
    /// exercising a planner-statistics hook.
    #[doc(hidden)]
    pub fn statistics_env_lock() -> &'static std::sync::Mutex<()> {
        brokk_bifrost_core::cache_gc::planner_statistics_test_lock()
    }
}
