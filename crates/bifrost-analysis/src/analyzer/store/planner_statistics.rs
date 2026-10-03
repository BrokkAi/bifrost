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
    /// Collection refreshes statistics through its own connection. Reload
    /// that result without sampling the same database a second time.
    pub(crate) fn reload_planner_statistics(&self) -> Result<()> {
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

    /// Refresh only when the stored statistics no longer describe the store.
    ///
    /// Returns `None` when nothing has been persisted or collected since the
    /// last refresh, which is what makes a repeated no-op build free.
    pub fn refresh_planner_statistics_if_stale(&self) -> Result<Option<PlannerStatisticsRefresh>> {
        let evidence = self
            .conn
            .execute(|conn| -> Result<Option<PlannerStatisticsRefresh>> {
                if planner_statistics_describe_database(conn).map_err(StoreError::new)? {
                    return Ok(None);
                }
                refresh_planner_statistics(conn)
                    .map(Some)
                    .map_err(StoreError::new)
            })?;
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
    use super::super::resolution_operation::selected_rust_declaration_authority_sql;
    use super::super::{
        AnalyzerStore, EXACT_PATH_SYMBOL_FQN_SQL, NORMALIZED_PATH_SYMBOL_FQN_SQL,
        REVERSE_IDENTIFIER_CANDIDATE_PATHS_SQL, REVERSE_IMPORT_CANDIDATE_BLOBS_SQL,
        REVERSE_TYPE_CANDIDATE_BLOBS_SQL, RUST_MODULE_IMPORT_CANDIDATE_BLOBS_SQL,
        RenderedTailMatch, Result, StoreError, WorkspaceSnapshots,
        batch_anchor_only_definition_candidate_sql, batch_component_definition_candidate_sql,
        candidate_fq_segments_sql, chunk_params, chunk_placeholders,
        direct_children_limited_candidate_sql, enclosing_declarations_for_file_sql,
        identifier_prefix_candidate_sql, limited_identifier_candidate_for_blob_sql,
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
                "selected_boundary_candidate_gap_branches",
                super::super::resolution_lexical::CANDIDATE_GAP_BOUNDARY_BRANCHES_SQL,
                vec![integer(5)],
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
        crate::analyzer::store::resolution_lexical::register_resolution_identity_functions(conn)
            .expect("resolution identity SQL functions");
        crate::analyzer::store::rust_crates::prepare_pin_context(conn).expect("crate SQL context");
        // The authority reader is normally planned against the selected
        // operation's connection, where this temp table is already installed.
        // Keep the registry self-contained for ephemeral planner-pin stores,
        // preserving the production mount table's WITHOUT ROWID key layout.
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS selected_resolution_overlay_masks(storage_language TEXT NOT NULL, persisted_relative_path TEXT NOT NULL, intent TEXT NOT NULL DEFAULT 'replacement', masked_file_version_id INTEGER, masked_blob_oid TEXT, masked_projection_digest BLOB, expected_transient_replacement_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(storage_language,persisted_relative_path)) WITHOUT ROWID;
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
             ) WITHOUT ROWID, STRICT;
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_typed_requests_1(
               mount_ordinal INTEGER NOT NULL CHECK(mount_ordinal >= 0),
               key0 INTEGER NOT NULL CHECK(key0 >= 0),
               PRIMARY KEY(mount_ordinal, key0)
             ) WITHOUT ROWID, STRICT;
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_typed_requests_2(
               mount_ordinal INTEGER NOT NULL CHECK(mount_ordinal >= 0),
               key0 INTEGER NOT NULL CHECK(key0 >= 0),
               key1 INTEGER NOT NULL CHECK(key1 >= 0),
               PRIMARY KEY(mount_ordinal, key0, key1)
             ) WITHOUT ROWID, STRICT;",
        )
        .expect("selected resolution mount pin table");
        conn.execute_batch(
            crate::analyzer::store::resolution_operation::go_context::GO_TRANSIENT_PLACEMENTS_SQL,
        )
        .expect("selected Go transient placement pin view");
        conn.execute_batch(crate::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_SCHEMA_SQL)
            .expect("selected Rust module placement pin view");
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
    }

    /// The typed-fact statements that take one blob and one key array, with the
    /// name each is pinned and planned under (milestone 6 port block 4, lane TF).
    ///
    /// The table is the one place the list lives: `pinned_queries` registers it
    /// and the plan pin below walks the same list, so a statement cannot be added
    /// to the reader and left unplanned.
    pub(super) const TYPED_FACT_PINS: &[(&str, &str)] = &[
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

    /// Every EXPLAIN QUERY PLAN pin this crate's store module owns, as data.
    ///
    /// This is where each of those statements is written, once. The pin tests
    /// in `store/mod.rs` fetch their subject from here with [`pinned`], and the
    /// two operator dumps below replay the whole list against a real
    /// repository store and against the captured statistics. Before this
    /// registry existed the dump carried its own copy of every statement and
    /// could drift from the test that asserts on it.
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
            "go_definition_package_anchor",
            super::super::resolution_operation::native_units::GO_DEFINITION_PACKAGE_ANCHOR,
            vec![integer(1)],
        ));
        queries.push(pin(
            "jvm_native_import_target_mounts",
            super::super::resolution_operation::jvm_context::JAVA_IMPORT_TARGET_MOUNTS,
            vec![text("dep")],
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
                "native_stage_package_references",
                package_context::STAGED_PACKAGE_REFERENCES,
                vec![integer(0)],
            ),
            (
                "native_stage_package_members",
                package_context::STAGED_MEMBERS,
                vec![integer(1), integer(1)],
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
                vec![text(&serde_json::to_string(&requests).expect("prefix pin parameters")), Value::Integer(crate::analyzer::store::resolution_prepare::resolution_rows::namespace_code(brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type))],
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
        queries.extend(root_terminal_demand_queries());
        queries.extend(
            crate::analyzer::store::rust_crates::sql_pins()
                .into_iter()
                .chain(crate::analyzer::store::resolution_operation::rust_crate_point_sql_pins())
                .map(|(name, sql, parameters)| pin(name, sql, vec![Value::Null; parameters])),
        );
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
                reverse::TARGET_ACTIVATION_SQL,
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
                vec![integer(1), text("crate")],
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
        ]);
        queries.extend([
            pin("rust_reverse_exports", include_str!("rust_reverse_exports.sql"), vec![integer(1), integer(0)]),
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
                 WHERE keys.lang = ? AND keys.blob_oid IN (?, ?)
                 ORDER BY keys.blob_oid, metadata.unit_key, metadata.ordinal"
            ),
            vec![text("java"), text(OID), text(OID)],
        ));
        queries.push(pin(
            "signature_metadata_for_unit_limited",
            signature_metadata_for_unit_sql(),
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

        // The manifest lookup is the hydration path's only statement that
        // joins and subqueries instead of seeking one primary key.
        queries.push(pin(
            "structural_fact_manifest",
            structural_fact_manifest_sql(),
            vec![text(OID), text("java"), integer(1)],
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
            "stage_go_definition_namespaces",
            super::super::resolution_stage::lexical_readers::GO_DEFINITION_NAMESPACES_SQL,
            vec![text("[1]")],
        ));

        queries.push(pin(
            "go_dot_import_target_mounts",
            super::super::resolution_operation::go_context::DOT_IMPORT_TARGET_MOUNTS,
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
            queries.push(pin(label, sql, vec![integer(1)]));
        }
        queries.push(pin(
            "go_named_import_package_name",
            super::super::resolution_operation::go_named::IMPORT_PACKAGE_NAME,
            vec![
                integer(1),
                integer(1),
                text("go"),
                text("example.test/provider"),
            ],
        ));
        queries.push(pin(
            "go_named_import_target_mounts",
            super::super::resolution_operation::go_named::NAMED_IMPORT_TARGET_MOUNTS,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "java_access_endpoints",
            super::super::resolution_typed::java_access::ENDPOINTS,
            vec![],
        ));
        queries.push(pin(
            "go_member_declarations",
            super::super::resolution_typed::go_members::DECLARATIONS,
            vec![],
        ));
        queries.push(pin(
            "java_inheritance_declarations",
            super::super::resolution_typed::java_inheritance::DECLARATIONS,
            vec![],
        ));
        queries.push(pin(
            "go_caller_source_role",
            super::super::resolution_operation::go_named::CALLER_SOURCE_ROLE,
            vec![integer(1), integer(1)],
        ));
        queries.push(pin(
            "go_caller_package",
            super::super::resolution_operation::go_same_package::CALLER_PACKAGE,
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
            vec![integer(1), integer(1), digest(1)],
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
        queries.push(pin(
            "class_set_summary_cascade_costs",
            stored_blob_cascade_costs_sql(1),
            vec![text(OID), text("python")],
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
                vec![digest(2)],
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
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
                 ORDER BY ordinal",
                super::super::IMPORT_STATEMENT_COLUMNS
            ),
            vec![text(OID), text("rust")],
        ));
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
        queries.push(pin(
            "selected_rust_declaration_authority",
            selected_rust_declaration_authority_sql(2),
            vec![integer(0), integer(11), integer(0), integer(17)],
        ));
        queries.push(pin(
            "selected_definition_units",
            super::super::selected_definition::SELECTED_DEFINITION_UNITS_SQL.as_str(),
            vec![],
        ));
        queries.push(pin(
            "selected_lexical_definitions",
            super::super::selected_definition::SELECTED_LEXICAL_DEFINITIONS_SQL,
            vec![],
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

    use super::super::{AnalyzerStore, WorkspaceId};
    // The pinned SQL, its bindings, and the two helpers that plan it live in
    // `pinned_plans` so the benchmark can call them too; the pin tests in
    // `store/mod.rs` still reach them through this module's path, which is why
    // the three they use are re-exported rather than merely imported.
    use super::pinned_plans::{OID, pinned_queries, plan_rows};
    pub(crate) use super::pinned_plans::{explain_pin, pinned, prepare_pin_context};
    use std::sync::Arc;

    use brokk_bifrost_core::cache_gc::{
        PlannerStatisticsState, STORE_STATISTICS_ENV, planner_statistics_repairs,
        planner_statistics_row_count, with_representative_statistics,
    };

    use crate::analyzer::workspace::WorkspaceAnalyzer;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject};
    use crate::gitblob::test_repo::{commit_all, init_repo};

    #[test]
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

    #[test]
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

    #[test]
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

    #[test]
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

    /// No production statement opens a resolution table outside tier 1.
    ///
    /// Tier 2 is computed on demand, so a statement that reads one of its
    /// families is reading rows the writer no longer produces. The check is
    /// structural: SQLite's own bytecode names every b-tree a statement
    /// opens through its root page, and `sqlite_schema` maps that root page
    /// back to a table. No source text is scanned, so a statement assembled
    /// at runtime is covered exactly as a literal one is.
    #[test]
    fn no_pinned_statement_opens_a_resolution_table_outside_tier_one() {
        let store = AnalyzerStore::open_ephemeral().expect("open store");
        let conn = store.conn.lock().expect("store mutex");
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .expect("workspace selection views");
        prepare_pin_context(&conn);
        let mut opened_any = false;
        for query in pinned_queries() {
            let mut statement = conn
                .prepare(&format!("EXPLAIN {}", query.sql))
                .unwrap_or_else(|error| {
                    panic!("pinned query {} does not prepare: {error}", query.name)
                });
            let roots = statement
                .query_map(rusqlite::params_from_iter(query.params.iter()), |row| {
                    Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
                })
                .expect("explain pinned query bytecode")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect pinned query bytecode")
                .into_iter()
                .filter(|(opcode, _)| opcode == "OpenRead")
                .map(|(_, root)| root)
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
                if !table.starts_with("resolution_") {
                    continue;
                }
                opened_any = true;
                assert!(
                    super::super::resolution::PERSISTED_RESOLUTION_TABLES.contains(&table.as_str()),
                    "pinned query {} opens {table}, which tier 1 does not persist",
                    query.name
                );
            }
        }
        assert!(
            opened_any,
            "the registry must contain at least one resolution reader for this pin to mean anything"
        );
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
    /// tree is restored to the first content and the retained workspace
    /// projection is released, so nothing owns the second blob any more.
    #[test]
    fn a_collection_that_drops_rows_refreshes_the_statistics() {
        let _guard = statistics_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = "pub fn widget() -> u32 { 1 }\n";
        let second = "pub fn widget() -> u32 { 2 }\npub fn extra() -> u32 { 3 }\n";
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();
        let repository = init_repo(&root);
        let first_commit = commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            Arc::clone(&project),
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        std::fs::write(root.join("app.rs"), second).unwrap();
        commit_all(&repository, "second content");
        drop(
            WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                Arc::clone(&project),
                AnalyzerConfig::default(),
            )
            .expect("persisted analyzer should rebuild"),
        );

        let head = repository.head().unwrap();
        let branch = head.name().expect("a named branch").to_string();
        repository
            .reference(&branch, first_commit, true, "drop the second commit")
            .unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();

        // Both analyzers are gone. Release their retained revision history;
        // rewinding Git alone does not make those facts collectable.
        let store = AnalyzerStore::open_persistent(&db_path).expect("open the collected store");
        assert!(
            store
                .delete_workspace_projection(&WorkspaceId::for_root(&root))
                .expect("release the workspace projection")
                > 0
        );
        drop(store);

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

    /// A pinned query whose plan the captured corpus statistics change, so a
    /// test can see which statistics a connection is planning with.
    ///
    /// The path-symbol lookups are the two pins that moved on all thirty-six
    /// corpus stores (issue #3016's corpus report), which is why one of them is
    /// the subject here.
    const STATISTICS_SENSITIVE_PIN: &str = "exact_path_symbol_fqn";

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

    /// A reader that was out while the statistics changed is closed when it
    /// comes back rather than returned to the idle set.
    ///
    /// This is the half a bare "drop the idle readers" recycle would miss: the
    /// reader checked out across the refresh is exactly the one a busy server
    /// has, and reusing it would keep the old plans indefinitely.
    #[test]
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

    /// A store that holds blobs but no statistics gets them when it is opened
    /// (issue #3031), and a store whose statistics are current does not pay for
    /// the check twice.
    ///
    /// The repair is counted rather than timed: `ANALYZE` on a one-blob store
    /// is too fast to distinguish from the open around it.
    #[test]
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

    /// An empty store is not analyzed on open.
    ///
    /// `ANALYZE` writes no row for an empty table, so a store with nothing in
    /// it would read as stale at every open and pay for a refresh that can
    /// produce nothing. Every ephemeral workspace opens exactly such a store.
    #[test]
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

    /// The end-to-end shape of the repair: a workspace built with the switch
    /// off carries no statistics, and the next open of that store -- with the
    /// switch cleared -- gives it some.
    #[test]
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

    /// Serializes the tests that set `BIFROST_STORE_STATISTICS`, which is
    /// process-wide state, with any other test that observes the switch while
    /// exercising a planner-statistics hook.
    fn statistics_env_lock() -> &'static std::sync::Mutex<()> {
        brokk_bifrost_core::cache_gc::planner_statistics_test_lock()
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

#[cfg(test)]
mod native_tests {
    use rusqlite::Connection;

    use super::super::ReaderPool;

    #[test]
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

    #[test]
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
             INSERT INTO rust_crate_container_sources SELECT 1, 'crate', id, 0, 'src/lib.rs', 'declared', NULL, NULL FROM blobs;
             INSERT INTO rust_crate_exports SELECT 1, 'crate', 'type', 'X', 'declaration',
                 'public', NULL, id, 0 FROM blobs;
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
                ("rust_reverse_exports", "rust_crate_exports_declaration"),
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
