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

/// Bound values of one statically sized row, in column order.
pub(crate) trait RowBindings {
    const ARITY: usize;

    fn append_values<'a>(&'a self, values: &mut Vec<&'a dyn ToSql>);
}

macro_rules! tuple_rows {
    (($($index:tt: $column:ident),*); $next:tt: $next_column:ident $(, $rest:tt: $rest_column:ident)*) => {
        impl<$($column: ToSql,)* $next_column: ToSql> RowBindings
            for ($($column,)* $next_column,)
        {
            const ARITY: usize = [$(stringify!($column),)* stringify!($next_column)].len();

            fn append_values<'a>(&'a self, values: &mut Vec<&'a dyn ToSql>) {
                values.extend([$(&self.$index as &dyn ToSql,)* &self.$next as &dyn ToSql]);
            }
        }
        tuple_rows!(($($index: $column,)* $next: $next_column); $($rest: $rest_column),*);
    };
    (($($index:tt: $column:ident),*);) => {};
}

// Signature metadata is the widest row: four keys and 38 value columns.
tuple_rows!(();
    0: C0, 1: C1, 2: C2, 3: C3, 4: C4, 5: C5, 6: C6,
    7: C7, 8: C8, 9: C9, 10: C10, 11: C11, 12: C12, 13: C13,
    14: C14, 15: C15, 16: C16, 17: C17, 18: C18, 19: C19, 20: C20,
    21: C21, 22: C22, 23: C23, 24: C24, 25: C25, 26: C26, 27: C27,
    28: C28, 29: C29, 30: C30, 31: C31, 32: C32, 33: C33, 34: C34,
    35: C35, 36: C36, 37: C37, 38: C38, 39: C39, 40: C40, 41: C41, 42: C42
);

/// Bind a slice of typed rows once, then use the shared statement batching.
pub(crate) fn insert_typed_rows<R: RowBindings>(
    conn: &Connection,
    insert_prefix: &str,
    row_sql: &str,
    rows: &[R],
    cancellation: &CancellationToken,
) -> rusqlite::Result<bool> {
    let mut values = Vec::with_capacity(rows.len() * R::ARITY);
    for row in rows {
        row.append_values(&mut values);
    }
    insert_rows(
        conn,
        insert_prefix,
        row_sql,
        R::ARITY,
        &values,
        cancellation,
    )
}

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
