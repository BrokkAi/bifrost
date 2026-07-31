use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use super::{CatalogError, CatalogOpenMode};

pub(super) const CATALOG_DB_FILE_NAME: &str = "catalog.db";
const CURRENT_CATALOG_VERSION: i64 = 2;
const BASELINE_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0001-current-baseline.sql");
const LIFECYCLE_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0002-lifecycle.sql");

pub(super) fn open(root: &Path, mode: CatalogOpenMode) -> Result<Connection, CatalogError> {
    let path = root.join(CATALOG_DB_FILE_NAME);
    let flags = match mode {
        CatalogOpenMode::ReadWrite => {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
        }
        CatalogOpenMode::ReadOnly => {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW
        }
    };
    let mut connection = Connection::open_with_flags(&path, flags)
        .map_err(|error| CatalogError::sqlite("open catalog", error))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| CatalogError::sqlite("configure busy timeout", error))?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| CatalogError::sqlite("read catalog schema version", error))?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    match mode {
        CatalogOpenMode::ReadWrite => configure_writer(&mut connection)?,
        CatalogOpenMode::ReadOnly => configure_reader(&connection)?,
    }
    migrate(&mut connection, mode)?;
    Ok(connection)
}

fn configure_writer(connection: &mut Connection) -> Result<(), CatalogError> {
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA recursive_triggers = ON;
             PRAGMA temp_store = MEMORY;",
        )
        .map_err(|error| CatalogError::sqlite("configure catalog writer", error))
}

fn configure_reader(connection: &Connection) -> Result<(), CatalogError> {
    connection
        .execute_batch(
            "PRAGMA query_only = ON;
             PRAGMA foreign_keys = ON;
             PRAGMA temp_store = MEMORY;",
        )
        .map_err(|error| CatalogError::sqlite("configure catalog reader", error))
}

fn migrate(connection: &mut Connection, mode: CatalogOpenMode) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| CatalogError::sqlite("read catalog schema version", error))?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version == CURRENT_CATALOG_VERSION {
        return Ok(());
    }
    if mode == CatalogOpenMode::ReadOnly {
        return Err(CatalogError::ReadOnlySchema {
            found: version,
            required: CURRENT_CATALOG_VERSION,
        });
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| CatalogError::sqlite("recheck catalog schema version", error))?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version == 0 {
        transaction
            .execute_batch(BASELINE_SQL)
            .map_err(|error| CatalogError::sqlite("apply catalog baseline", error))?;
    }
    if locked_version <= 1 {
        transaction
            .execute_batch(LIFECYCLE_SQL)
            .map_err(|error| CatalogError::sqlite("apply catalog lifecycle migration", error))?;
    }
    transaction
        .pragma_update(None, "user_version", CURRENT_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration", error))
}
