//! The shared per-unit resolution summary: one writer and one reconcile driver
//! for every language, and the one validity predicate the writer and every
//! reader use (derivation contract, kind 2; see
//! `.agents/docs/architecture-and-analyzer-store.md`).
//!
//! A language supplies its unit definition and its derivation through
//! [`UnitSummaryLanguage`]. The driver owns the algorithm: it orders the units
//! bottom-up, computes each unit's `summary_digest` from its own inputs and from
//! the output digests of the units it consumed, reuses a summary whose digest
//! already exists, derives and publishes the rest one transaction per unit, and
//! closes the version rows it did not rebind.
//!
//! Unit of work: one unit. Retained after the call: rows in SQLite only. The
//! ordering of units lives in session temp tables that the driver empties before
//! it returns, and the only Rust heap structure is the rows of the unit being
//! published, dropped with its transaction.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{AnalyzerStore, Result, StoreError, WorkspaceSnapshotId};
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};

/// One file of a unit: the unit's own input.
pub(crate) struct UnitMember {
    pub blob_id: i64,
    pub blob_oid: String,
    pub rel_path: String,
    pub source_role: String,
}

/// A recorded input that is neither a member nor a child summary.
pub(crate) struct UnitRead {
    pub kind: &'static str,
    pub key_digest: [u8; 32],
    pub digest: [u8; 32],
}

/// A unit this one consumes. A workspace dependency that is itself a unit names
/// its `unit_id` so the driver can look up the child's live summary; an external
/// or standard-library dependency names the digest of the provenance it saw.
pub(crate) struct UnitDependency {
    pub unit_key: [u8; 32],
    pub unit_id: Option<i64>,
    pub label: String,
    pub boundary: &'static str,
    pub provenance: Option<String>,
    pub external_digest: Option<[u8; 32]>,
}

pub(crate) struct UnitInputs {
    pub unit_id: i64,
    pub unit_key: [u8; 32],
    pub label: String,
    pub members: Vec<UnitMember>,
    pub reads: Vec<UnitRead>,
    pub dependencies: Vec<UnitDependency>,
}

/// One dependency as the derivation consumed it. `available` is false for a
/// workspace dependency that had no live summary at this pass; the digest is then
/// a marker that differs from every real output digest, so a dependent derived
/// without it is derived again when the dependency appears.
pub(crate) struct ConsumedDependency {
    pub ordinal: usize,
    pub unit_key: [u8; 32],
    pub label: String,
    pub consumed_output_digest: [u8; 32],
    pub boundary: &'static str,
    pub available: bool,
}

pub(crate) struct UnitExport {
    pub identity_id: i64,
    pub identity_digest: [u8; 32],
    pub namespace: String,
    pub visibility: &'static str,
    pub origin: &'static str,
    pub alias_dependency_ordinal: Option<usize>,
    pub alias_identity_id: Option<i64>,
    /// Stable semantic content for `alias_identity_id`; row ids are store-local.
    pub alias_identity_digest: Option<[u8; 32]>,
    pub declaration_blob_id: i64,
    pub declaration_site: i64,
    pub declaration_key: i64,
}

pub(crate) struct UnitImport {
    pub blob_id: i64,
    /// The blob's `source_imports.import_id`.
    pub import_id: i64,
    /// `named`, `blank` or `dot`.
    pub kind: &'static str,
    /// The blob-local import binding key; absent for a dot import.
    pub definition_key: Option<i64>,
    pub spelling: String,
    pub dependency_ordinal: Option<usize>,
    pub state: &'static str,
}

pub(crate) struct UnitGap {
    pub kind: &'static str,
    pub subject: String,
    /// A JSON document, stored as JSONB.
    pub detail: String,
}

pub(crate) struct UnitOutputs {
    pub exports: Vec<UnitExport>,
    pub imports: Vec<UnitImport>,
    pub gaps: Vec<UnitGap>,
    pub complete: bool,
}

/// What a language supplies. Every method runs on the store's writer
/// connection, inside one reconcile.
pub(crate) trait UnitSummaryLanguage {
    fn lang(&self) -> &'static str;
    fn unit_kind(&self) -> &'static str;
    fn derivation_version(&self) -> i64;

    /// Fill `temp.unit_summary_work` with one row per unit and
    /// `temp.unit_summary_edges` with one row per consumed workspace unit. Both
    /// hold language-assigned integer unit ids; an edge must name two units of
    /// the work table.
    fn stage(&self, conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<()>;

    /// Clear language-owned TEMP rows before this query-scoped reconcile
    /// returns. The default is enough for adapters that stage directly into
    /// the shared work and edge tables.
    fn clear_stage(&self, _conn: &Connection) -> Result<()> {
        Ok(())
    }

    fn inputs(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit_id: i64,
    ) -> Result<UnitInputs>;

    /// The live summary of one unit under this language's validity predicate:
    /// its summary id and output digest. The default is the shared predicate;
    /// a language that keeps more than one live profile adds the profile match.
    fn live_summary(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        producer_epoch: &str,
        unit_key: &[u8; 32],
    ) -> Result<Option<(i64, Vec<u8>)>> {
        Ok(conn
            .prepare_cached(LIVE_SUMMARY_SQL)?
            .query_row(
                params![
                    snapshot.workspace_id.as_str(),
                    self.lang(),
                    snapshot.generation.get(),
                    unit_key.as_slice(),
                    snapshot.revision,
                    producer_epoch,
                    self.derivation_version()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    fn derive(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        dependencies: &[ConsumedDependency],
        producer_epoch: &str,
    ) -> Result<UnitOutputs>;
}

/// What one reconcile pass did, for profiling and for the caller to report.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UnitSummaryReconciliation {
    pub units: usize,
    /// Units whose live version row already pointed at the digest's summary.
    pub unchanged: usize,
    /// Units rebound to an existing summary, without derivation.
    pub rebound: usize,
    pub derived: usize,
    /// Rows written by derived units (header, children and version rows).
    pub rows_written: usize,
    /// Output digest changes among derived units that already had a live summary.
    pub output_changes: usize,
    pub closed_versions: usize,
    /// Units whose derivation failed and so publish nothing, with the error.
    pub failed: Vec<(String, String)>,
    pub cancelled: bool,
    /// Wall time of the whole pass: the time the writer job holds the writer.
    pub elapsed: Duration,
    /// Time inside unit transactions, in total and for the longest one: the
    /// time another process's writer can be held off.
    pub transaction_total: Duration,
    pub transaction_max: Duration,
    /// The most rows one derived unit wrote.
    pub max_unit_rows: usize,
    /// Statements the writer connection ran for the pass and for the busiest
    /// unit. Counted only when the store carries a statement counter, which is
    /// test and measurement builds; zero otherwise.
    pub statements: usize,
    pub max_unit_statements: usize,
}

/// The select the validity predicate is written in, once. A version row open at
/// the selected revision, a complete summary, and the active producer epoch and
/// derivation version. A language that records more than one live profile adds
/// its own conjunct to this text (`GO_LIVE_SUMMARY_SQL` adds the profile read);
/// the writer and every reader use that one statement.
macro_rules! live_summary_select {
    () => {
        "SELECT versions.summary_id, summaries.output_digest
     FROM resolution_unit_summary_versions AS versions
     JOIN resolution_unit_summaries AS summaries ON summaries.summary_id = versions.summary_id
     WHERE versions.workspace_id = ?1 AND versions.lang = ?2 AND versions.generation = ?3
       AND versions.unit_key = ?4
       AND versions.valid_from <= ?5 AND (versions.valid_until IS NULL OR ?5 < versions.valid_until)
       AND summaries.publication_state = 'complete'
       AND summaries.producer_epoch = ?6 AND summaries.derivation_version = ?7"
    };
}
pub(crate) use live_summary_select;

/// The child's live summary for a language with one live profile. Go uses
/// `GO_LIVE_SUMMARY_SQL`, which adds the profile read.
pub(crate) const LIVE_SUMMARY_SQL: &str = live_summary_select!();

/// One name in one unit's export relation: the point reader's statement.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const UNIT_EXPORT_POINT_SQL: &str =
    "SELECT declaration_blob_id, declaration_site, declaration_key, visibility
     FROM resolution_unit_summary_exports
     WHERE summary_id = ?1 AND namespace = ?2 AND identity_id = ?3";

/// The live units that consume one unit: the dependents the reconcile adds to
/// its work list when an output digest moved, and the reverse reader's unit
/// candidates. `CROSS JOIN` fixes the join order: without planner statistics
/// SQLite otherwise walks every version row of the workspace and probes the
/// dependency rows from each, which scales with units times revisions instead
/// of with the dependents of one unit.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const UNIT_DEPENDENTS_SQL: &str = "SELECT versions.unit_key
     FROM resolution_unit_summary_dependencies AS dependencies
     CROSS JOIN resolution_unit_summary_versions AS versions ON versions.summary_id = dependencies.summary_id
     WHERE dependencies.dependency_unit_key = ?1 AND versions.workspace_id = ?2
       AND versions.lang = ?3 AND versions.generation = ?4 AND versions.valid_until IS NULL";

/// The graph stage's join: each member's root-reaching reference paths against
/// the unit's own export relation. `CROSS JOIN` fixes the order members, paths,
/// exports, so the work is one export probe per root-reaching path; the planner's
/// own choice without statistics probes the paths index once per member and
/// export instead.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const UNIT_GRAPH_JOIN_SQL: &str =
    "SELECT members.blob_id, paths.path, exports.declaration_blob_id, exports.declaration_site
     FROM resolution_unit_summary_members AS members
     CROSS JOIN resolution_paths AS paths INDEXED BY resolution_paths_root_terminal
       ON paths.blob_id = members.blob_id AND paths.root_terminal IS NOT NULL
     CROSS JOIN resolution_unit_summary_exports AS exports
       ON exports.summary_id = members.summary_id AND exports.identity_id = paths.root_terminal
     WHERE members.summary_id = ?1";

/// Persist-path hook for a replaced blob. `write_prepared_blob_rows_tx` deletes and
/// re-inserts a blob row when the same content is persisted again (a repair or a
/// producer rewrite), and the member, export and import rows that reference the
/// old row cascade away. Every version row of every summary that listed the blob
/// as a member is withdrawn in the same transaction, so the validity rule stays
/// "a live version row and a complete header": a reader never finds a complete
/// header whose rows are gone, and falls back until the next reconcile derives
/// the unit again. Closed rows go too, because a reader selecting an older
/// revision would otherwise read the same hollow summary. The statement seeks
/// `blobs(blob_oid, lang)`, `resolution_unit_summary_members(blob_id)` and
/// `resolution_unit_summary_versions(summary_id)`.
pub(super) const WITHDRAW_VERSIONS_OF_REPLACED_BLOB_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions
     WHERE summary_id IN (
       SELECT members.summary_id
       FROM blobs
       JOIN resolution_unit_summary_members AS members ON members.blob_id = blobs.id
       WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2)";

/// Withdraw one workspace's version rows (`delete_workspace_projection`).
pub(super) const DELETE_WORKSPACE_VERSIONS_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions WHERE workspace_id = ?1";

/// Withdraw every version row of one language (analysis epoch rotation).
pub(super) const DELETE_LANGUAGE_VERSIONS_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions WHERE lang = ?1";

/// Withdraw the version rows of generations the language epoch has left behind
/// (stale-generation reclaim; the rotation hook normally already did).
pub(super) const DELETE_STALE_GENERATION_VERSIONS_SQL: &str =
    "DELETE FROM resolution_unit_summary_versions
     WHERE generation <> COALESCE(
       (SELECT generation FROM analysis_epochs
        WHERE analysis_epochs.lang = resolution_unit_summary_versions.lang), 0)";

/// Delete the headers no version row binds; the children cascade. Shared
/// headers that another workspace still binds stay.
pub(super) const DELETE_UNBOUND_SUMMARIES_SQL: &str = "DELETE FROM resolution_unit_summaries
     WHERE NOT EXISTS (SELECT 1 FROM resolution_unit_summary_versions AS versions
                       WHERE versions.summary_id = resolution_unit_summaries.summary_id)";

const OPEN_VERSION_SQL: &str = "SELECT summary_id, valid_from FROM resolution_unit_summary_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND unit_key = ?4
       AND valid_until IS NULL";
const INSERT_VERSION_SQL: &str = "INSERT INTO resolution_unit_summary_versions(workspace_id, lang, generation, unit_key, valid_from, valid_until, summary_id)
     VALUES(?1, ?2, ?3, ?4, ?5, NULL, ?6)";
const CLOSE_VERSION_SQL: &str = "UPDATE resolution_unit_summary_versions SET valid_until = ?5
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND unit_key = ?4
       AND valid_until IS NULL";
// An open row that this very revision opened has the empty interval [R, R), which
// the schema rejects; it is withdrawn instead (see `rust_crates.rs`
// `end_open_crate_version`).
const WITHDRAW_VERSION_SQL: &str = "DELETE FROM resolution_unit_summary_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND unit_key = ?4
       AND valid_until IS NULL AND valid_from = ?5";

const FIND_SUMMARY_SQL: &str = "SELECT summary_id,
       publication_state = 'complete'
       AND member_count = (SELECT count(*) FROM resolution_unit_summary_members WHERE summary_id = summaries.summary_id)
       AND export_count = (SELECT count(*) FROM resolution_unit_summary_exports WHERE summary_id = summaries.summary_id)
       AND import_count = (SELECT count(*) FROM resolution_unit_summary_imports WHERE summary_id = summaries.summary_id)
     FROM resolution_unit_summaries AS summaries WHERE summary_digest = ?1";

// Close every open row this pass did not rebind. A row opened by this revision
// is withdrawn; an earlier one is closed at this revision.
const WITHDRAW_UNSETTLED_SQL: &str = "DELETE FROM resolution_unit_summary_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND valid_until IS NULL AND valid_from = ?4
       AND NOT EXISTS (SELECT 1 FROM temp.unit_summary_order AS settled
                       WHERE settled.unit_key = resolution_unit_summary_versions.unit_key)";
const CLOSE_UNSETTLED_SQL: &str = "UPDATE resolution_unit_summary_versions SET valid_until = ?4
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND valid_until IS NULL AND valid_from < ?4
       AND NOT EXISTS (SELECT 1 FROM temp.unit_summary_order AS settled
                       WHERE settled.unit_key = resolution_unit_summary_versions.unit_key)";
const LATER_OPEN_VERSION_SQL: &str = "SELECT EXISTS(SELECT 1 FROM resolution_unit_summary_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND valid_until IS NULL AND valid_from > ?4)";

const STAGING_SCHEMA_SQL: &str = "
CREATE TEMP TABLE IF NOT EXISTS unit_summary_work(unit_id INTEGER PRIMARY KEY) STRICT;
CREATE TEMP TABLE IF NOT EXISTS unit_summary_edges(
  unit_id INTEGER NOT NULL,
  dependency_unit_id INTEGER NOT NULL,
  PRIMARY KEY(unit_id, dependency_unit_id)
) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS unit_summary_order(
  ordinal INTEGER PRIMARY KEY,
  unit_id INTEGER NOT NULL UNIQUE,
  unit_key BLOB UNIQUE
) STRICT;
DELETE FROM temp.unit_summary_work;
DELETE FROM temp.unit_summary_edges;
DELETE FROM temp.unit_summary_order;";

const CLEAR_STAGING_SQL: &str = "
DELETE FROM temp.unit_summary_work;
DELETE FROM temp.unit_summary_edges;
DELETE FROM temp.unit_summary_order;";

// One wave of Kahn's algorithm: every unit all of whose consumed units are
// already ordered. SQLite materializes this SELECT before inserting because the
// target table is read in it, so a wave never sees its own rows.
const ORDER_WAVE_SQL: &str = "INSERT INTO temp.unit_summary_order(unit_id)
     SELECT work.unit_id FROM temp.unit_summary_work AS work
     WHERE NOT EXISTS (SELECT 1 FROM temp.unit_summary_order AS ordered WHERE ordered.unit_id = work.unit_id)
       AND NOT EXISTS (
         SELECT 1 FROM temp.unit_summary_edges AS edges
         WHERE edges.unit_id = work.unit_id AND edges.dependency_unit_id <> work.unit_id
           AND NOT EXISTS (SELECT 1 FROM temp.unit_summary_order AS ordered
                           WHERE ordered.unit_id = edges.dependency_unit_id))
     ORDER BY work.unit_id";
// Units on a dependency cycle never become ready. They are ordered last and are
// derived without consuming each other, because a dependency that is not settled
// is unavailable to its dependents.
const ORDER_REMAINDER_SQL: &str = "INSERT INTO temp.unit_summary_order(unit_id)
     SELECT work.unit_id FROM temp.unit_summary_work AS work
     WHERE NOT EXISTS (SELECT 1 FROM temp.unit_summary_order AS ordered WHERE ordered.unit_id = work.unit_id)
     ORDER BY work.unit_id";
const NEXT_UNIT_SQL: &str = "SELECT ordinal, unit_id FROM temp.unit_summary_order
     WHERE ordinal > ?1 ORDER BY ordinal LIMIT 1";
const SETTLE_UNIT_SQL: &str = "UPDATE temp.unit_summary_order SET unit_key = ?2 WHERE unit_id = ?1";
const SETTLED_UNIT_SQL: &str =
    "SELECT unit_key FROM temp.unit_summary_order WHERE unit_id = ?1 AND unit_key IS NOT NULL";

impl AnalyzerStore {
    /// Reconcile one language's unit summaries against one workspace snapshot.
    ///
    /// Runs as one writer job: the units, their inputs and their derivations are
    /// read on the writer connection, so a child published a moment ago is
    /// visible to its dependents. Each unit is its own transaction, so another
    /// process's writer is never held off for more than one unit.
    pub(crate) fn reconcile_unit_summaries(
        &self,
        snapshot: &WorkspaceSnapshotId,
        language: impl UnitSummaryLanguage + Send + 'static,
        cancellation: &CancellationToken,
    ) -> Result<UnitSummaryReconciliation> {
        assert_eq!(snapshot.lang, language.lang());
        let snapshot = snapshot.clone();
        let cancellation = cancellation.clone();
        let statements = self.statement_counter();
        self.conn.execute(move |conn| {
            let started = Instant::now();
            let statements_before = statements.count();
            let _trace = StatementCount::register(conn, &statements);
            let mut report = reconcile(conn, &snapshot, &language, &cancellation, &statements)?;
            report.elapsed = started.elapsed();
            report.statements = statements.count() - statements_before;
            Ok(report)
        })
    }

    /// The counter a measurement installs on the store, or an inert one.
    fn statement_counter(&self) -> StatementCounter {
        #[cfg(test)]
        {
            StatementCounter(self.crate_statement_counter.lock().unwrap().clone())
        }
        #[cfg(not(test))]
        {
            StatementCounter(None)
        }
    }
}

/// Statements run on the writer connection, when a measurement asked for them.
#[derive(Clone)]
struct StatementCounter(Option<Arc<AtomicUsize>>);

impl StatementCounter {
    fn count(&self) -> usize {
        self.0
            .as_ref()
            .map_or(0, |counter| counter.load(Ordering::Relaxed))
    }
}

/// Registers `sqlite3_trace_v2` statement counting on the writer connection for
/// the length of one pass. It holds the raw handle, not a borrow, because the
/// pass needs `&mut Connection` for its transactions.
struct StatementCount {
    handle: Option<*mut rusqlite::ffi::sqlite3>,
}

impl StatementCount {
    fn register(conn: &Connection, counter: &StatementCounter) -> Self {
        unsafe extern "C" fn count(
            event: std::ffi::c_uint,
            context: *mut std::ffi::c_void,
            _: *mut std::ffi::c_void,
            _: *mut std::ffi::c_void,
        ) -> std::ffi::c_int {
            if event == rusqlite::ffi::SQLITE_TRACE_STMT {
                // SAFETY: the pass retains the counter's Arc until it unregisters.
                let counter = unsafe { &*context.cast::<AtomicUsize>() };
                counter.fetch_add(1, Ordering::Relaxed);
            }
            0
        }
        let Some(counter) = &counter.0 else {
            return Self { handle: None };
        };
        // SAFETY: the callback keeps no SQLite pointer, and `Drop` unregisters it
        // before the connection or the counter's Arc is released.
        let handle = unsafe { conn.handle() };
        let status = unsafe {
            rusqlite::ffi::sqlite3_trace_v2(
                handle,
                rusqlite::ffi::SQLITE_TRACE_STMT,
                Some(count),
                Arc::as_ptr(counter).cast_mut().cast(),
            )
        };
        assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        Self {
            handle: Some(handle),
        }
    }
}

impl Drop for StatementCount {
    fn drop(&mut self) {
        if let Some(handle) = self.handle {
            // SAFETY: unregisters the callback registered by `register`.
            let status =
                unsafe { rusqlite::ffi::sqlite3_trace_v2(handle, 0, None, std::ptr::null_mut()) };
            assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        }
    }
}

fn reconcile(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    cancellation: &CancellationToken,
    statements: &StatementCounter,
) -> Result<UnitSummaryReconciliation> {
    conn.execute_batch(STAGING_SCHEMA_SQL)?;
    let outcome = reconcile_staged(conn, snapshot, language, cancellation, statements);
    // The staging rows are this pass's working set and never outlive it.
    language.clear_stage(conn)?;
    conn.execute_batch(CLEAR_STAGING_SQL)?;
    outcome
}

fn reconcile_staged(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    cancellation: &CancellationToken,
    statements: &StatementCounter,
) -> Result<UnitSummaryReconciliation> {
    let mut report = UnitSummaryReconciliation::default();
    language.stage(conn, snapshot)?;
    while conn.execute(ORDER_WAVE_SQL, [])? > 0 {}
    conn.execute(ORDER_REMAINDER_SQL, [])?;
    report.units = conn.query_row("SELECT count(*) FROM temp.unit_summary_order", [], |row| {
        row.get::<_, usize>(0)
    })?;
    let producer_epoch: Option<String> = conn
        .query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = ?1",
            [snapshot.lang.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if report.units > 0 {
        let producer_epoch = producer_epoch.as_deref().ok_or_else(|| {
            StoreError::corrupt(format!(
                "{} has {} units but no resolution producer epoch",
                snapshot.lang, report.units
            ))
        })?;
        let mut after = 0_i64;
        loop {
            if cancellation.is_cancelled() {
                report.cancelled = true;
                break;
            }
            let next: Option<(i64, i64)> = conn
                .query_row(NEXT_UNIT_SQL, [after], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()?;
            let Some((ordinal, unit_id)) = next else {
                break;
            };
            after = ordinal;
            let statements_before = statements.count();
            publish_unit(
                conn,
                snapshot,
                language,
                producer_epoch,
                unit_id,
                cancellation,
                &mut report,
            )?;
            report.max_unit_statements = report
                .max_unit_statements
                .max(statements.count() - statements_before);
        }
    }
    close_unsettled(conn, snapshot, language, &mut report)?;
    Ok(report)
}

/// Publish one unit: reuse its summary when the digest exists, otherwise derive
/// and write it, then bind the version row. A unit whose inputs or derivation
/// fail publishes nothing and is not settled, so the end of the pass closes its
/// open version row; the failure is reported, not propagated, so one bad unit
/// does not withhold the others. Store errors still propagate.
fn publish_unit(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    producer_epoch: &str,
    unit_id: i64,
    cancellation: &CancellationToken,
    report: &mut UnitSummaryReconciliation,
) -> Result<()> {
    let unit = match language.inputs(conn, snapshot, unit_id) {
        Ok(unit) => unit,
        Err(error) => {
            report.failed.push((
                format!("{} unit {unit_id}", language.lang()),
                error.to_string(),
            ));
            return Ok(());
        }
    };
    let dependencies = consume_dependencies(conn, snapshot, language, producer_epoch, &unit)?;
    let digest = summary_digest(language, snapshot, producer_epoch, &unit, &dependencies);
    let existing = find_summary(conn, &digest)?;
    let open = open_version(conn, snapshot, language, &unit.unit_key)?;
    let publication = if let (Some(existing), Some((open_summary, _))) = (&existing, open)
        && existing.intact
        && existing.summary_id == open_summary
    {
        UnitPublication::Unchanged
    } else {
        let transaction_started = Instant::now();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut rows_written = 0;
        let (summary_id, derived_output) = match existing {
            Some(existing) if existing.intact => (existing.summary_id, None),
            existing => {
                let outputs =
                    match language.derive(&tx, snapshot, &unit, &dependencies, producer_epoch) {
                        Ok(outputs) => outputs,
                        Err(error) => {
                            report.failed.push((unit.label.clone(), error.to_string()));
                            return Ok(());
                        }
                    };
                if cancellation.is_cancelled() {
                    report.cancelled = true;
                    return Ok(());
                }
                let output_digest = output_digest(&dependencies, &outputs);
                let summary_id = write_summary(
                    &tx,
                    language,
                    producer_epoch,
                    &digest,
                    existing.map(|existing| existing.summary_id),
                    &unit,
                    &dependencies,
                    &outputs,
                    &output_digest,
                    &mut rows_written,
                )?;
                (summary_id, Some(output_digest))
            }
        };
        let previous_output = match open {
            Some((open_summary, _)) if open_summary != summary_id => tx
                .query_row(
                    "SELECT output_digest FROM resolution_unit_summaries WHERE summary_id = ?1",
                    [open_summary],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            _ => None,
        };
        if let Some((open_summary, opened)) = open
            && open_summary != summary_id
        {
            end_open_version(&tx, snapshot, language, &unit.unit_key, opened)?;
            rows_written += 1;
        }
        if open.is_none_or(|(open_summary, _)| open_summary != summary_id) {
            tx.execute(
                INSERT_VERSION_SQL,
                params![
                    snapshot.workspace_id.as_str(),
                    language.lang(),
                    snapshot.generation.get(),
                    unit.unit_key.as_slice(),
                    snapshot.revision,
                    summary_id
                ],
            )?;
            rows_written += 1;
        }
        tx.commit()?;
        let held = transaction_started.elapsed();
        report.transaction_total += held;
        report.transaction_max = report.transaction_max.max(held);
        report.max_unit_rows = report.max_unit_rows.max(rows_written);
        match derived_output {
            Some(output_digest) => UnitPublication::Derived {
                rows_written,
                output_changed: previous_output
                    .is_some_and(|previous| previous.as_slice() != output_digest.as_slice()),
            },
            None => UnitPublication::Rebound { rows_written },
        }
    };
    conn.prepare_cached(SETTLE_UNIT_SQL)?
        .execute(params![unit_id, unit.unit_key.as_slice()])?;
    match publication {
        UnitPublication::Unchanged => report.unchanged += 1,
        UnitPublication::Rebound { rows_written } => {
            report.rebound += 1;
            report.rows_written += rows_written;
        }
        UnitPublication::Derived {
            rows_written,
            output_changed,
        } => {
            report.derived += 1;
            report.rows_written += rows_written;
            report.output_changes += usize::from(output_changed);
        }
    }
    Ok(())
}

enum UnitPublication {
    Unchanged,
    Rebound {
        rows_written: usize,
    },
    Derived {
        rows_written: usize,
        output_changed: bool,
    },
}

struct ExistingSummary {
    summary_id: i64,
    /// Complete, with every blob-referencing child still present. A blob row
    /// replaced since publication cascades its children away, and the counts
    /// stored in the header no longer match.
    intact: bool,
}

fn find_summary(conn: &Connection, digest: &[u8; 32]) -> Result<Option<ExistingSummary>> {
    Ok(conn
        .prepare_cached(FIND_SUMMARY_SQL)?
        .query_row([digest.as_slice()], |row| {
            Ok(ExistingSummary {
                summary_id: row.get(0)?,
                intact: row.get(1)?,
            })
        })
        .optional()?)
}

fn open_version(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    unit_key: &[u8; 32],
) -> Result<Option<(i64, i64)>> {
    Ok(conn
        .prepare_cached(OPEN_VERSION_SQL)?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                unit_key.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

fn end_open_version(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    unit_key: &[u8; 32],
    opened: i64,
) -> Result<()> {
    let changed = match opened.cmp(&snapshot.revision) {
        std::cmp::Ordering::Less => conn.execute(
            CLOSE_VERSION_SQL,
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                snapshot.revision
            ],
        )?,
        std::cmp::Ordering::Equal => conn.execute(
            WITHDRAW_VERSION_SQL,
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                snapshot.revision
            ],
        )?,
        std::cmp::Ordering::Greater => {
            return Err(StoreError::new(format!(
                "{} unit summary reconcile at revision {} of workspace {} generation {} found \
                 unit {} open since the later revision {opened}",
                language.lang(),
                snapshot.revision,
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                lower_hex_string(unit_key)
            )));
        }
    };
    assert_eq!(
        changed,
        1,
        "unit {} must have exactly one open version row",
        lower_hex_string(unit_key)
    );
    Ok(())
}

fn close_unsettled(
    conn: &mut Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    report: &mut UnitSummaryReconciliation,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let later: bool = tx.query_row(
        LATER_OPEN_VERSION_SQL,
        params![
            snapshot.workspace_id.as_str(),
            language.lang(),
            snapshot.generation.get(),
            snapshot.revision
        ],
        |row| row.get(0),
    )?;
    if later {
        return Err(StoreError::new(format!(
            "{} unit summary reconcile at revision {} of workspace {} generation {} found a \
             version open since a later revision",
            language.lang(),
            snapshot.revision,
            snapshot.workspace_id.as_str(),
            snapshot.generation.get()
        )));
    }
    for statement in [WITHDRAW_UNSETTLED_SQL, CLOSE_UNSETTLED_SQL] {
        report.closed_versions += tx.execute(
            statement,
            params![
                snapshot.workspace_id.as_str(),
                language.lang(),
                snapshot.generation.get(),
                snapshot.revision
            ],
        )?;
    }
    // A profile replacement or a failed unit unbinds headers; delete them with
    // the rows that bound them.
    if report.closed_versions > 0 {
        tx.execute(DELETE_UNBOUND_SUMMARIES_SQL, [])?;
    }
    tx.commit()?;
    Ok(())
}

/// Resolve each consumed unit to its live summary's output digest. A workspace
/// dependency counts only when this pass already settled it: a live row from an
/// earlier revision has not been checked against this revision's inputs.
fn consume_dependencies(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    language: &dyn UnitSummaryLanguage,
    producer_epoch: &str,
    unit: &UnitInputs,
) -> Result<Vec<ConsumedDependency>> {
    let mut sorted: Vec<&UnitDependency> = unit.dependencies.iter().collect();
    sorted.sort_by_key(|dependency| dependency.unit_key);
    assert!(
        sorted
            .windows(2)
            .all(|pair| pair[0].unit_key != pair[1].unit_key),
        "unit {} lists a dependency twice: {:?}",
        unit.label,
        unit.dependencies
            .iter()
            .map(|dependency| dependency.label.as_str())
            .collect::<Vec<_>>()
    );
    let mut consumed = Vec::with_capacity(sorted.len());
    for (ordinal, dependency) in sorted.into_iter().enumerate() {
        let live = match dependency.unit_id {
            Some(dependency_unit_id) => {
                let settled: Option<Vec<u8>> = conn
                    .prepare_cached(SETTLED_UNIT_SQL)?
                    .query_row([dependency_unit_id], |row| row.get(0))
                    .optional()?;
                match settled {
                    Some(_) => language
                        .live_summary(conn, snapshot, producer_epoch, &dependency.unit_key)?
                        .map(|(_, output)| output),
                    None => None,
                }
            }
            None => None,
        };
        let (digest, available) = match (live, dependency.external_digest) {
            (Some(output), _) => (digest_from_row(output)?, true),
            (None, Some(external)) => (external, true),
            (None, None) => (unavailable_digest(&dependency.unit_key), false),
        };
        consumed.push(ConsumedDependency {
            ordinal,
            unit_key: dependency.unit_key,
            label: dependency.label.clone(),
            consumed_output_digest: digest,
            boundary: dependency.boundary,
            available,
        });
    }
    Ok(consumed)
}

fn unavailable_digest(unit_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-unavailable:v1");
    hash.field("unit", unit_key);
    hash.finish()
}

fn digest_from_row(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|value: Vec<u8>| StoreError::corrupt(format!("digest is {} bytes", value.len())))
}

/// The identity digest: the unit's own inputs and the consumed output digests.
/// Equal inputs give an equal digest, so a unit whose members, recorded reads and
/// consumed outputs did not move is reused without derivation, and an unmoved
/// output digest of a dependency leaves its dependents' digests unmoved.
fn summary_digest(
    language: &dyn UnitSummaryLanguage,
    snapshot: &WorkspaceSnapshotId,
    producer_epoch: &str,
    unit: &UnitInputs,
    dependencies: &[ConsumedDependency],
) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary:v2");
    hash.field("lang", language.lang().as_bytes());
    hash.field("unit-kind", language.unit_kind().as_bytes());
    hash.field(
        "derivation-version",
        &language.derivation_version().to_be_bytes(),
    );
    hash.field("producer-epoch", producer_epoch.as_bytes());
    hash.field("generation", &snapshot.generation.get().to_be_bytes());
    hash.field("unit", &unit.unit_key);
    for member in &unit.members {
        hash.field("member-path", member.rel_path.as_bytes());
        hash.field("member-role", member.source_role.as_bytes());
        hash.field("member-oid", member.blob_oid.as_bytes());
    }
    let mut reads: Vec<&UnitRead> = unit.reads.iter().collect();
    reads.sort_by_key(|read| read.key_digest);
    for read in reads {
        hash.field("read-kind", read.kind.as_bytes());
        hash.field("read-key", &read.key_digest);
        hash.field("read-digest", &read.digest);
    }
    for dependency in dependencies {
        hash.field("dependency", &dependency.unit_key);
        hash.field("dependency-digest", &dependency.consumed_output_digest);
        hash.field("dependency-boundary", dependency.boundary.as_bytes());
    }
    hash.finish()
}

/// The digest of what a dependent can see of a unit: its exports (identity,
/// namespace, visibility, origin and alias target), whether it is complete, and the
/// `conflicting_names` gaps (two declarations of one name). It leaves out
/// declaration blob ids, sites and keys, and dependency ordinals, which name
/// where a declaration lives or a dependency sits rather than what the unit exports.
/// It leaves out imports, which are not visible to dependents. So an edit that
/// keeps the surface keeps this digest and stops at the unit's dependents.
/// Readers never copy coordinates out of a summary, so an equal digest cannot
/// leave a stale coordinate behind.
fn output_digest(dependencies: &[ConsumedDependency], outputs: &UnitOutputs) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-output:v4");
    hash.field("complete", &[u8::from(outputs.complete)]);
    let mut exports: Vec<_> = outputs
        .exports
        .iter()
        .map(|export| {
            let alias_dependency_key = export.alias_dependency_ordinal.map(|ordinal| {
                dependencies
                    .iter()
                    .find(|dependency| dependency.ordinal == ordinal)
                    .unwrap_or_else(|| {
                        panic!(
                            "export identity {} references dependency ordinal {ordinal}; consumed dependencies: {:?}",
                            export.identity_id,
                            dependencies
                                .iter()
                                .map(|dependency| (dependency.ordinal, dependency.unit_key))
                                .collect::<Vec<_>>()
                        )
                    })
                    .unit_key
            });
            (
                export.identity_digest,
                export.namespace.as_str(),
                export.visibility,
                export.origin,
                alias_dependency_key,
                export.alias_identity_digest,
            )
        })
        .collect();
    exports.sort_unstable();
    exports.dedup();
    for (identity, namespace, visibility, origin, alias_dependency_key, alias_identity) in exports {
        hash.field("export-identity", &identity);
        hash.field("export-namespace", namespace.as_bytes());
        hash.field("export-visibility", visibility.as_bytes());
        hash.field("export-origin", origin.as_bytes());
        match alias_dependency_key {
            Some(key) => {
                hash.field("export-alias-dependency-present", &[1]);
                hash.field("export-alias-dependency-key", &key);
            }
            None => hash.field("export-alias-dependency-present", &[0]),
        }
        match alias_identity {
            Some(identity) => {
                hash.field("export-alias-identity-present", &[1]);
                hash.field("export-alias-identity", &identity);
            }
            None => hash.field("export-alias-identity-present", &[0]),
        }
    }
    let mut conflicts: Vec<_> = outputs
        .gaps
        .iter()
        .filter(|gap| gap.kind == "conflicting_names")
        .map(|gap| gap.subject.as_str())
        .collect();
    conflicts.sort_unstable();
    conflicts.dedup();
    for subject in conflicts {
        hash.field("conflicting-subject", subject.as_bytes());
    }
    hash.finish()
}

/// Write one summary's header and children and seal it. `replace` is the header
/// of a summary with this digest whose blob-referencing children were lost: it is
/// rebuilt in place, so version rows that point at it stay valid.
#[allow(clippy::too_many_arguments)]
fn write_summary(
    tx: &Connection,
    language: &dyn UnitSummaryLanguage,
    producer_epoch: &str,
    digest: &[u8; 32],
    replace: Option<i64>,
    unit: &UnitInputs,
    dependencies: &[ConsumedDependency],
    outputs: &UnitOutputs,
    output_digest: &[u8; 32],
    rows_written: &mut usize,
) -> Result<i64> {
    let summary_id = match replace {
        Some(summary_id) => {
            tx.execute(
                "UPDATE resolution_unit_summaries SET publication_state = 'building',
                        output_digest = NULL, member_count = 0, export_count = 0, import_count = 0
                 WHERE summary_id = ?1",
                [summary_id],
            )?;
            for table in [
                "resolution_unit_summary_imports",
                "resolution_unit_summary_exports",
                "resolution_unit_summary_gaps",
                "resolution_unit_summary_reads",
                "resolution_unit_summary_dependencies",
                "resolution_unit_summary_members",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE summary_id = ?1"),
                    [summary_id],
                )?;
            }
            summary_id
        }
        None => {
            tx.prepare_cached(
                "INSERT INTO resolution_unit_summaries(lang, unit_kind, unit_key, summary_digest,
                        producer_epoch, derivation_version, complete, publication_state)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, 'building')",
            )?
            .execute(params![
                language.lang(),
                language.unit_kind(),
                unit.unit_key.as_slice(),
                digest.as_slice(),
                producer_epoch,
                language.derivation_version()
            ])?;
            tx.last_insert_rowid()
        }
    };
    *rows_written += 1;
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO resolution_unit_summary_members(summary_id, member_ordinal, blob_id, rel_path, source_role)
             VALUES(?1, ?2, ?3, ?4, ?5)",
        )?;
        for (ordinal, member) in unit.members.iter().enumerate() {
            insert.execute(params![
                summary_id,
                ordinal,
                member.blob_id,
                member.rel_path,
                member.source_role
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO resolution_unit_summary_dependencies(summary_id, dependency_ordinal,
                    dependency_unit_key, consumed_output_digest, boundary, provenance)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        let provenance: std::collections::HashMap<[u8; 32], Option<&str>> = unit
            .dependencies
            .iter()
            .map(|dependency| (dependency.unit_key, dependency.provenance.as_deref()))
            .collect();
        for dependency in dependencies {
            insert.execute(params![
                summary_id,
                dependency.ordinal,
                dependency.unit_key.as_slice(),
                dependency.consumed_output_digest.as_slice(),
                dependency.boundary,
                provenance[&dependency.unit_key]
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO resolution_unit_summary_reads(summary_id, read_ordinal, kind, key_digest, digest)
             VALUES(?1, ?2, ?3, ?4, ?5)",
        )?;
        let mut reads: Vec<&UnitRead> = unit.reads.iter().collect();
        reads.sort_by_key(|read| read.key_digest);
        for (ordinal, read) in reads.into_iter().enumerate() {
            insert.execute(params![
                summary_id,
                ordinal,
                read.kind,
                read.key_digest.as_slice(),
                read.digest.as_slice()
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO resolution_unit_summary_exports(summary_id, identity_id, namespace, visibility,
                    origin, alias_dependency_ordinal, alias_identity_id, declaration_blob_id,
                    declaration_site, declaration_key)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for export in &outputs.exports {
            insert.execute(params![
                summary_id,
                export.identity_id,
                export.namespace,
                export.visibility,
                export.origin,
                export.alias_dependency_ordinal,
                export.alias_identity_id,
                export.declaration_blob_id,
                export.declaration_site,
                export.declaration_key
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO resolution_unit_summary_imports(summary_id, blob_id, import_id, kind,
                    import_definition_key, dependency_ordinal, state)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for import in &outputs.imports {
            insert.execute(params![
                summary_id,
                import.blob_id,
                import.import_id,
                import.kind,
                import.definition_key,
                import.dependency_ordinal,
                import.state
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO resolution_unit_summary_gaps(summary_id, gap_kind, subject, detail)
             VALUES(?1, ?2, ?3, jsonb(?4))",
        )?;
        for gap in &outputs.gaps {
            insert.execute(params![summary_id, gap.kind, gap.subject, gap.detail])?;
        }
    }
    let counts = |table: &str| -> Result<usize> {
        Ok(tx.query_row(
            &format!("SELECT count(*) FROM {table} WHERE summary_id = ?1"),
            [summary_id],
            |row| row.get(0),
        )?)
    };
    let (members, exports, imports) = (
        counts("resolution_unit_summary_members")?,
        counts("resolution_unit_summary_exports")?,
        counts("resolution_unit_summary_imports")?,
    );
    assert_eq!(members, unit.members.len(), "member rows of {}", unit.label);
    assert_eq!(
        exports,
        outputs.exports.len(),
        "export rows of {}",
        unit.label
    );
    assert_eq!(
        imports,
        outputs.imports.len(),
        "import rows of {}",
        unit.label
    );
    assert_eq!(
        counts("resolution_unit_summary_dependencies")?,
        dependencies.len(),
        "dependency rows of {}",
        unit.label
    );
    *rows_written +=
        members + exports + imports + dependencies.len() + unit.reads.len() + outputs.gaps.len();
    tx.execute(
        "UPDATE resolution_unit_summaries SET complete = ?2, member_count = ?3, export_count = ?4,
                import_count = ?5, output_digest = ?6, publication_state = 'complete'
         WHERE summary_id = ?1",
        params![
            summary_id,
            outputs.complete,
            members,
            exports,
            imports,
            output_digest.as_slice()
        ],
    )?;
    Ok(summary_id)
}
