//! Multi-row INSERT for the writer's per-blob row loops.
//!
//! The persistent writer is the one thread every language's parse workers
//! wait on during a cold build, and almost all of its time is single-row
//! INSERTs (#6390). Each statement execution pays its own setup, and on a
//! table with a row trigger SQLite also opens a statement journal and copies
//! every page the row touches into it before changing it. With this store's
//! 32 KiB pages that copy dominates: a single-row insert into a
//! trigger-guarded source table cost about 20 us where the same row in a
//! 100-row statement cost about 7. Batching keeps the rows, their order, and
//! the per-row trigger and constraint checks exactly as they were; only the
//! number of statements changes.

use rusqlite::{Connection, ToSql, params_from_iter};

use crate::CancellationToken;

/// Rows per statement, largest first. A blob's rows go out in as many
/// 64-row statements as fit, then 8-row ones, then single rows, so a table
/// prepares at most three statements and few rows go out alone.
const ROWS_PER_STATEMENT: [usize; 3] = [64, 8, 1];

/// SQLite's default ceiling on bound parameters per statement
/// (SQLITE_MAX_VARIABLE_NUMBER in the bundled build).
const MAX_BOUND_PARAMETERS: usize = 32_766;

/// Insert `values.len() / arity` rows into one table, in order, using the
/// statement sizes in [`ROWS_PER_STATEMENT`].
///
/// `insert_prefix` is everything before the row tuples, for example
/// `INSERT INTO t(blob_id, a, b) VALUES`, and `row_sql` is one tuple with
/// anonymous placeholders, for example `(?, ?, jsonb(?))`. `values` holds the
/// bound values of every row back to back. Returns false, having inserted a
/// prefix of the rows, when `cancellation` fires before a statement, the way
/// the per-row loops it replaces checked before each row.
pub(crate) fn insert_rows(
    conn: &Connection,
    insert_prefix: &str,
    row_sql: &str,
    arity: usize,
    values: &[&dyn ToSql],
    cancellation: &CancellationToken,
) -> rusqlite::Result<bool> {
    assert!(
        arity > 0,
        "{insert_prefix} binds at least one value per row"
    );
    assert_eq!(
        values.len() % arity,
        0,
        "{insert_prefix} received a partial row"
    );
    assert!(
        arity * ROWS_PER_STATEMENT[0] <= MAX_BOUND_PARAMETERS,
        "{insert_prefix} binds {arity} values per row, too many for {}-row statements",
        ROWS_PER_STATEMENT[0]
    );
    debug_assert_eq!(
        row_sql.matches('?').count(),
        arity,
        "{row_sql} must have one placeholder per bound value"
    );
    let mut rest = values;
    for rows in ROWS_PER_STATEMENT {
        let width = arity * rows;
        if rest.len() < width {
            continue;
        }
        let sql = format!("{insert_prefix} {}", vec![row_sql; rows].join(", "));
        let mut statement = conn.prepare_cached(&sql)?;
        let mut chunks = rest.chunks_exact(width);
        for chunk in chunks.by_ref() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            statement.execute(params_from_iter(chunk))?;
        }
        rest = chunks.remainder();
    }
    debug_assert!(
        rest.is_empty(),
        "single-row statements take every remaining row"
    );
    Ok(true)
}
