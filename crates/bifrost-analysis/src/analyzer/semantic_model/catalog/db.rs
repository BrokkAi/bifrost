use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use super::{CatalogError, CatalogOpenMode};

pub(super) const CATALOG_DB_FILE_NAME: &str = "catalog.db";
const CURRENT_CATALOG_VERSION: i64 = 4;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const INITIALIZATION_RETRY_BACKOFF: Duration = Duration::from_millis(5);
const INITIALIZATION_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(100);
const BASELINE_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0001-current-baseline.sql");
const LIFECYCLE_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0002-lifecycle.sql");
const PROCEDURE_SUMMARIES_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0003-procedure-summaries.sql");
const GENERATED_PRODUCTIONS_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0004-generated-productions.sql");

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
        .busy_timeout(BUSY_TIMEOUT)
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
    ensure_wal_journal_mode(connection)?;
    connection
        .execute_batch(
            "PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA recursive_triggers = ON;
             PRAGMA temp_store = MEMORY;",
        )
        .map_err(|error| CatalogError::sqlite("configure catalog writer", error))
}

fn ensure_wal_journal_mode(connection: &Connection) -> Result<(), CatalogError> {
    let started = Instant::now();
    let mut backoff = INITIALIZATION_RETRY_BACKOFF;
    loop {
        match set_wal_journal_mode(connection) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                return Err(CatalogError::Integrity(
                    "SQLite did not enable WAL mode for the semantic-pack catalog".to_owned(),
                ));
            }
            Err(error) if error.sqlite_error_code() == Some(ErrorCode::DatabaseBusy) => {
                let elapsed = started.elapsed();
                if elapsed >= BUSY_TIMEOUT {
                    return Err(CatalogError::sqlite(
                        "configure catalog journal mode",
                        error,
                    ));
                }
                std::thread::sleep(backoff.min(BUSY_TIMEOUT.saturating_sub(elapsed)));
                backoff = backoff
                    .saturating_mul(2)
                    .min(INITIALIZATION_RETRY_MAX_BACKOFF);
            }
            Err(error) => {
                return Err(CatalogError::sqlite(
                    "configure catalog journal mode",
                    error,
                ));
            }
        }
    }
}

fn set_wal_journal_mode(connection: &Connection) -> rusqlite::Result<bool> {
    let current: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if current.eq_ignore_ascii_case("wal") {
        return Ok(true);
    }
    let updated: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    Ok(updated.eq_ignore_ascii_case("wal"))
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
    if locked_version <= 2 {
        transaction
            .execute_batch(PROCEDURE_SUMMARIES_SQL)
            .map_err(|error| CatalogError::sqlite("apply procedure-summary migration", error))?;
    }
    if locked_version <= 3 {
        transaction
            .execute_batch(GENERATED_PRODUCTIONS_SQL)
            .map_err(|error| CatalogError::sqlite("apply generated-production migration", error))?;
    }
    transaction
        .pragma_update(None, "user_version", CURRENT_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration", error))
}
