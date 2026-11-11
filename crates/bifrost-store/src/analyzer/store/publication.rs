//! Two-phase publication over the `publication_state` column.
//!
//! A writer inserts a head row as building, writes its child rows in the same
//! transaction, then seals the head. Readers see a head only once it is
//! complete. The column and its CHECK constraint stay as they are; this module
//! names the states and owns the seal transition.

use rusqlite::Connection;
use rusqlite::ToSql;

use super::Result;
use super::StoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationState {
    Building,
    Complete,
}

impl PublicationState {
    pub(crate) const fn as_sql(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Complete => "complete",
        }
    }

    pub(crate) fn from_sql(value: &str) -> Result<Self> {
        match value {
            "building" => Ok(Self::Building),
            "complete" => Ok(Self::Complete),
            other => Err(StoreError::new(format!(
                "publication_state holds {other:?}, not building or complete"
            ))),
        }
    }
}

/// The reader predicate for a sealed head. Qualify it with the head table's
/// alias (`{alias}.{IS_COMPLETE}`) when the statement joins more than one
/// table. Pinned statements written as literals keep their own text.
pub(crate) const IS_COMPLETE: &str = "publication_state = 'complete'";

/// Seal the building head `table.key_column = key` in the writing transaction,
/// setting `columns` in the same UPDATE so a complete head never lacks them.
/// Exactly one row must move from building to complete.
pub(super) fn seal(
    tx: &Connection,
    table: &str,
    key_column: &str,
    key: i64,
    columns: &[(&str, &dyn ToSql)],
) -> Result<()> {
    let mut assignments = String::new();
    for (index, (column, _)) in columns.iter().enumerate() {
        assignments.push_str(&format!("{column} = ?{}, ", index + 2));
    }
    let sql = format!(
        "UPDATE {table} SET {assignments}publication_state = '{}'
         WHERE {key_column} = ?1 AND publication_state = '{}'",
        PublicationState::Complete.as_sql(),
        PublicationState::Building.as_sql(),
    );
    let mut params = Vec::with_capacity(columns.len() + 1);
    params.push(&key as &dyn ToSql);
    params.extend(columns.iter().map(|(_, value)| *value));
    let sealed = tx.prepare_cached(&sql)?.execute(params.as_slice())?;
    assert_eq!(
        sealed, 1,
        "{table} head {key_column} = {key} was not building when it was sealed"
    );
    Ok(())
}
