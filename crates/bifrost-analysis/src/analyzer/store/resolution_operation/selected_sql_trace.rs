//! SQL tracing shared by engine tests and tool-surface performance regressions.

use super::super::AnalyzerStore;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use std::cell::RefCell;

#[cfg(any(test, feature = "test-support"))]
use std::collections::BTreeMap;

use std::sync::Mutex;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

#[derive(Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct ProductionSelectedSqlCost {
    pub statements: Vec<String>,
    /// Rows decoded by the execution at the same index in `statements`.
    /// Each SQLite statement pointer identifies its latest traced execution,
    /// so an outer cursor retains its row ownership while nested statements
    /// execute. Reusing a statement pointer starts a new execution entry.
    #[doc(hidden)]
    pub rows_by_statement: Vec<usize>,
    /// SQLite schema parsing emits ROW for an internal statement with no SQL
    /// text and hence no STMT event. Keep these rows explicit, never assigned
    /// to the outer DDL or a recycled statement pointer.
    #[doc(hidden)]
    pub internal_schema_rows: usize,
    #[doc(hidden)]
    pub decoded_rows: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl ProductionSelectedSqlCost {
    #[doc(hidden)]
    pub fn statement_count(&self) -> usize {
        self.statements.len()
    }

    /// Decoded rows and executions grouped by statement text, most rows first.
    #[doc(hidden)]
    pub fn rows_by_shape(&self) -> Vec<(usize, usize, &str)> {
        assert_eq!(self.statements.len(), self.rows_by_statement.len());
        let mut totals: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for (sql, rows) in self.statements.iter().zip(self.rows_by_statement.iter()) {
            let entry = totals.entry(sql.as_str()).or_default();
            entry.0 += rows;
            entry.1 += 1;
        }
        let mut shapes = totals
            .into_iter()
            .map(|(sql, (rows, executions))| (rows, executions, sql))
            .collect::<Vec<_>>();
        if self.internal_schema_rows != 0 {
            shapes.push((
                self.internal_schema_rows,
                0,
                "<SQLite internal schema rows: no STMT event>",
            ));
        }
        assert_eq!(
            self.decoded_rows,
            self.rows_by_statement.iter().sum::<usize>() + self.internal_schema_rows
        );
        shapes.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.2.cmp(right.2)));
        shapes
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn point_read_freshness_groups(cost: &ProductionSelectedSqlCost) -> usize {
    // Each selected read group starts with one complete freshness triple.
    // Check that structure as well as the measured number of groups, including
    // callable-result projections and one wildcard page per 120 mounts.
    let groups = cost
        .statements
        .split(|sql| sql == "PRAGMA main.data_version")
        .skip(1)
        .collect::<Vec<_>>();
    assert!(
        !groups.is_empty(),
        "selected point search must emit freshness groups"
    );
    for (index, group) in groups.iter().enumerate() {
        assert_eq!(
            group.first().map(String::as_str),
            Some("PRAGMA main.schema_version"),
            "freshness group {index} must read main schema version: {groups:?}"
        );
        assert_eq!(
            group.get(1).map(String::as_str),
            Some("PRAGMA temp.schema_version"),
            "freshness group {index} must read temp schema version: {groups:?}"
        );
    }
    let freshness_groups = groups.len();
    // Only the page containing the demanded lookup issues the keyed wildcard
    // probe. Empty foreign pages still perform their freshness checks.
    for pragma in [
        "PRAGMA main.data_version",
        "PRAGMA main.schema_version",
        "PRAGMA temp.schema_version",
    ] {
        assert_eq!(
            cost.statements.iter().filter(|sql| *sql == pragma).count(),
            freshness_groups,
            "every emitted selected read group must have one {pragma} boundary"
        );
    }
    freshness_groups
}

struct ProductionSelectedSqlTraceContext {
    cost: Mutex<ProductionSelectedSqlCost>,
    executions: Mutex<crate::hash::HashMap<usize, usize>>,
    failed: AtomicBool,
}

impl Default for ProductionSelectedSqlTraceContext {
    fn default() -> Self {
        Self {
            cost: Mutex::new(ProductionSelectedSqlCost::default()),
            executions: Mutex::new(crate::hash::HashMap::default()),
            failed: AtomicBool::new(false),
        }
    }
}

thread_local! {
    static PRODUCTION_SELECTED_SQL_TRACE: RefCell<Option<Box<ProductionSelectedSqlTraceContext>>> =
        const { RefCell::new(None) };
    #[cfg(any(test, feature = "test-support"))]
    static TRACE_CONTEXT_PUBLICATION_WORK: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static TRACE_SELECTED_MOUNT_CALLERS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

// Scoped to the scaling diagnostic; unwind also restores the callback policy.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct SelectedMountCallerTrace;

#[cfg(any(test, feature = "test-support"))]
impl SelectedMountCallerTrace {
    #[doc(hidden)]
    pub fn begin() -> Self {
        TRACE_SELECTED_MOUNT_CALLERS.with(|enabled| assert!(!enabled.replace(true)));
        Self
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for SelectedMountCallerTrace {
    fn drop(&mut self) {
        TRACE_SELECTED_MOUNT_CALLERS.with(|enabled| assert!(enabled.replace(false)));
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct ContextPublicationWorkTrace;

#[cfg(any(test, feature = "test-support"))]
impl ContextPublicationWorkTrace {
    #[doc(hidden)]
    pub fn begin() -> Self {
        TRACE_CONTEXT_PUBLICATION_WORK.with(|enabled| assert!(!enabled.replace(true)));
        Self
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for ContextPublicationWorkTrace {
    fn drop(&mut self) {
        TRACE_CONTEXT_PUBLICATION_WORK.with(|enabled| assert!(enabled.replace(false)));
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn context_publication_work(
    session: &ResolutionSession,
) -> Option<ReceiverAnalysisWork> {
    TRACE_CONTEXT_PUBLICATION_WORK.with(|enabled| enabled.get().then(|| session.finish(()).work()))
}

unsafe extern "C" fn record_production_selected_sql(
    event: std::ffi::c_uint,
    context: *mut std::ffi::c_void,
    statement: *mut std::ffi::c_void,
    raw_sql: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    let result = std::panic::catch_unwind(|| {
        assert!(!context.is_null(), "SQLite trace must have shared state");
        // SAFETY: registration owns this stable boxed context until it removes
        // the callback; SQLite invokes the callback synchronously per statement.
        let trace = unsafe { &*context.cast::<ProductionSelectedSqlTraceContext>() };
        match event {
            rusqlite::ffi::SQLITE_TRACE_STMT => {
                assert!(!raw_sql.is_null(), "SQLite statement trace must name SQL");
                // SAFETY: SQLITE_TRACE_STMT supplies a callback-lifetime SQL C string.
                let sql = unsafe { std::ffi::CStr::from_ptr(raw_sql.cast()) }
                    .to_string_lossy()
                    .into_owned();
                if TRACE_SELECTED_MOUNT_CALLERS.with(std::cell::Cell::get)
                    && sql.starts_with("SELECT mount_ordinal,fragment_id,workspace_id")
                    && sql.contains("FROM temp.selected_resolution_mounts WHERE mount_ordinal=?1")
                {
                    eprintln!(
                        "selected mount-record caller: {}",
                        std::backtrace::Backtrace::force_capture()
                    );
                }
                assert!(!statement.is_null());
                let mut cost = trace.cost.lock().expect("production SQL trace cost lock");
                let mut executions = trace
                    .executions
                    .lock()
                    .expect("production SQL trace executions lock");
                executions.insert(statement as usize, cost.statements.len());
                cost.statements.push(sql);
                cost.rows_by_statement.push(0);
            }
            rusqlite::ffi::SQLITE_TRACE_ROW => {
                let mut cost = trace.cost.lock().expect("production SQL trace cost lock");
                cost.decoded_rows = cost
                    .decoded_rows
                    .checked_add(1)
                    .expect("production selected decoded row count fits usize");
                // SAFETY: SQLITE_TRACE_ROW supplies a live sqlite3_stmt.
                let sql = unsafe { rusqlite::ffi::sqlite3_sql(statement.cast()) };
                // Bundled SQLite skips SetSql while init.busy, suppressing
                // STMT in OP_Init; OP_ResultRow still emits every ROW.
                if sql.is_null() {
                    cost.internal_schema_rows += 1;
                } else {
                    let execution = trace
                        .executions
                        .lock()
                        .expect("production SQL trace executions lock")
                        .get(&(statement as usize))
                        .copied()
                        .unwrap_or_else(|| {
                            // SAFETY: sqlite3_sql text lives with this statement.
                            let sql = unsafe { std::ffi::CStr::from_ptr(sql) };
                            panic!("a named row requires its traced execution: {sql:?}");
                        });
                    cost.rows_by_statement[execution] += 1;
                }
            }
            _ => unreachable!("production selected SQL trace registered known events only"),
        }
    });
    if result.is_err() {
        // SAFETY: the registered trace context outlives this callback.
        unsafe { &*context.cast::<ProductionSelectedSqlTraceContext>() }
            .failed
            .store(true, Ordering::SeqCst);
    }
    0
}

#[doc(hidden)]
pub fn begin_production_selected_sql_trace_on_connection(connection: &rusqlite::Connection) {
    let context = PRODUCTION_SELECTED_SQL_TRACE.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.is_none(), "production selected SQL trace cannot nest");
        *slot = Some(Box::default());
        slot.as_deref_mut()
            .expect("production selected SQL trace is installed")
            as *mut ProductionSelectedSqlTraceContext
    });
    // SAFETY: the connection outlives the callback; its user pointer names
    // the stable Box retained until the callback is removed.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(
            connection.handle(),
            rusqlite::ffi::SQLITE_TRACE_STMT | rusqlite::ffi::SQLITE_TRACE_ROW,
            Some(record_production_selected_sql),
            context.cast(),
        )
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
}

#[doc(hidden)]
pub fn finish_production_selected_sql_trace_on_connection(
    connection: &rusqlite::Connection,
) -> ProductionSelectedSqlCost {
    // SAFETY: this is the connection registered above. A zero mask removes
    // the callback before its shared context is freed.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(connection.handle(), 0, None, std::ptr::null_mut())
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
    let cost = checkpoint_production_selected_sql_trace();
    PRODUCTION_SELECTED_SQL_TRACE.with(|slot| {
        slot.borrow_mut()
            .take()
            .expect("production selected SQL trace must be active");
    });
    cost
}

#[test]
fn production_selected_sql_trace_attributes_nested_cursor_rows() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    begin_production_selected_sql_trace_on_connection(&connection);
    // The table has one schema entry and no implicit index. SQLite's
    // OP_ParseSchema reads that entry through a SQL-less internal statement.
    connection
        .execute_batch("CREATE TABLE trace_schema_probe(value INTEGER)")
        .unwrap();
    let schema = checkpoint_production_selected_sql_trace();
    let mut outer = connection
        .prepare("SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3")
        .unwrap();
    let mut inner = connection.prepare("SELECT 10 UNION ALL SELECT 20").unwrap();
    {
        let mut rows = outer.query([]).unwrap();
        while rows.next().unwrap().is_some() {
            let mut nested = inner.query([]).unwrap();
            while nested.next().unwrap().is_some() {}
        }
    }
    let nested = checkpoint_production_selected_sql_trace();
    {
        let mut rows = inner.query([]).unwrap();
        while rows.next().unwrap().is_some() {}
    }
    let repeated = finish_production_selected_sql_trace_on_connection(&connection);
    assert_eq!(schema.statement_count(), 1);
    assert_eq!(schema.rows_by_statement, [0]);
    assert_eq!(schema.internal_schema_rows, 1);
    assert_eq!(schema.decoded_rows, 1);
    assert_eq!(nested.internal_schema_rows, 0);
    assert_eq!(repeated.internal_schema_rows, 0);
    assert_eq!(nested.statement_count(), 4);
    assert_eq!(nested.decoded_rows, 9);
    assert_eq!(nested.rows_by_statement, [3, 2, 2, 2]);
    assert_eq!(repeated.statement_count(), 1);
    assert_eq!(repeated.decoded_rows, 2);
    assert_eq!(repeated.rows_by_statement, [2]);
}

#[doc(hidden)]
pub fn begin_production_selected_sql_trace(store: &AnalyzerStore) {
    let connection = store
        .active_read_conn()
        .expect("check out the next production selected reader");
    begin_production_selected_sql_trace_on_connection(&connection);
}

#[doc(hidden)]
pub fn checkpoint_production_selected_sql_trace() -> ProductionSelectedSqlCost {
    // Callers checkpoint after closing cursors. No execution crosses a checkpoint.
    PRODUCTION_SELECTED_SQL_TRACE.with(|slot| {
        let slot = slot.borrow();
        let trace = slot
            .as_deref()
            .expect("production selected SQL trace must be active");
        let failed = trace.failed.swap(false, Ordering::SeqCst);
        let mut cost = trace.cost.lock().expect("production SQL trace cost lock");
        let mut executions = trace
            .executions
            .lock()
            .expect("production SQL trace executions lock");
        *executions = crate::hash::HashMap::default();
        let result = std::mem::take(&mut *cost);
        assert!(!failed, "production selected SQL trace callback panicked");
        result
    })
}

#[doc(hidden)]
pub fn finish_production_selected_sql_trace(store: &AnalyzerStore) -> ProductionSelectedSqlCost {
    let connection = store
        .active_read_conn()
        .expect("check out the traced production selected reader");
    let cost = finish_production_selected_sql_trace_on_connection(&connection);
    drop(connection);
    cost
}
