use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use super::{CatalogError, CatalogOpenMode};

pub(super) const CATALOG_DB_FILE_NAME: &str = "catalog.db";
pub(super) const CURRENT_CATALOG_VERSION: i64 = 6;
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
const EXTRACTION_GAPS_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0005-extraction-gaps.sql");
const EXTRACTION_SOURCE_ENTRIES_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0006-extraction-source-entries.sql");

pub(super) fn open(root: &Path, mode: CatalogOpenMode) -> Result<Connection, CatalogError> {
    // The catalog is the other database a Bifrost process can open first, and
    // the memory-statistics knob is only settable before the first connection.
    crate::cache_db::disable_sqlite_memory_statistics();
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
    let version: i64 =
        retry_initialization(|| connection.query_row("PRAGMA user_version", [], |row| row.get(0)))
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
    let enabled = retry_initialization(|| set_wal_journal_mode(connection))
        .map_err(|error| CatalogError::sqlite("configure catalog journal mode", error))?;
    if !enabled {
        return Err(CatalogError::Integrity(
            "SQLite did not enable WAL mode for the semantic-pack catalog".to_owned(),
        ));
    }
    Ok(())
}

fn retry_initialization<T>(operation: impl FnMut() -> rusqlite::Result<T>) -> rusqlite::Result<T> {
    retry_initialization_with(BUSY_TIMEOUT, std::thread::sleep, operation)
}

fn retry_initialization_with<T>(
    deadline: Duration,
    mut sleep: impl FnMut(Duration),
    mut operation: impl FnMut() -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    let started = Instant::now();
    let mut backoff = INITIALIZATION_RETRY_BACKOFF;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if is_transient_initialization_error(&error) => {
                let elapsed = started.elapsed();
                if elapsed >= deadline {
                    return Err(error);
                }
                sleep(backoff.min(deadline.saturating_sub(elapsed)));
                if started.elapsed() >= deadline {
                    return Err(error);
                }
                backoff = backoff
                    .saturating_mul(2)
                    .min(INITIALIZATION_RETRY_MAX_BACKOFF);
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_transient_initialization_error(error: &rusqlite::Error) -> bool {
    // Concurrent first openers can surface SQLITE_PROTOCOL while Windows
    // negotiates the WAL locking protocol. Keep that retry scoped to catalog
    // initialization; the same error during normal catalog work is terminal.
    matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::FileLockingProtocolFailed)
    )
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
    let version: i64 =
        retry_initialization(|| connection.query_row("PRAGMA user_version", [], |row| row.get(0)))
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
    let locked_version: i64 =
        retry_initialization(|| transaction.query_row("PRAGMA user_version", [], |row| row.get(0)))
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
    if locked_version <= 4 {
        transaction
            .execute_batch(EXTRACTION_GAPS_SQL)
            .map_err(|error| CatalogError::sqlite("apply extraction-gap migration", error))?;
    }
    if locked_version <= 5 {
        transaction
            .execute_batch(EXTRACTION_SOURCE_ENTRIES_SQL)
            .map_err(|error| {
                CatalogError::sqlite("apply extraction-source-entry migration", error)
            })?;
    }
    transaction
        .pragma_update(None, "user_version", CURRENT_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration", error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_error(code: i32) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
    }

    #[test]
    fn initialization_retry_admits_busy_and_locking_protocol_failures() {
        let mut attempts = 0;
        let value = retry_initialization_with(
            Duration::from_secs(1),
            |_| {},
            || {
                attempts += 1;
                match attempts {
                    1 => Err(sqlite_error(rusqlite::ffi::SQLITE_BUSY)),
                    2 => Err(sqlite_error(rusqlite::ffi::SQLITE_PROTOCOL)),
                    _ => Ok(42),
                }
            },
        )
        .unwrap();

        assert_eq!(value, 42);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn initialization_retry_does_not_admit_other_sqlite_errors() {
        let mut attempts = 0;
        let error = retry_initialization_with(
            Duration::from_secs(1),
            |_| {},
            || {
                attempts += 1;
                Err::<(), _>(sqlite_error(rusqlite::ffi::SQLITE_LOCKED))
            },
        )
        .unwrap_err();

        assert_eq!(error.sqlite_error_code(), Some(ErrorCode::DatabaseLocked));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn initialization_retry_returns_transient_error_at_deadline() {
        let mut attempts = 0;
        let error = retry_initialization_with(
            Duration::ZERO,
            |_| panic!("an expired retry must not sleep"),
            || {
                attempts += 1;
                Err::<(), _>(sqlite_error(rusqlite::ffi::SQLITE_PROTOCOL))
            },
        )
        .unwrap_err();

        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::FileLockingProtocolFailed)
        );
        assert_eq!(attempts, 1);
    }
}
