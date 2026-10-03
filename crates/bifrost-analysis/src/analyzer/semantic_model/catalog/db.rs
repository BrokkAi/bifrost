use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use super::{CatalogError, CatalogOpenMode};

pub(super) const CATALOG_DB_FILE_NAME: &str = "catalog.db";
pub(super) const CURRENT_CATALOG_VERSION: i64 = 11;
const PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION: i64 = 10;
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
const ACQUISITION_ABSENCE_RECEIPTS_SQL: &str = include_str!(
    "../../../../migrations/semantic-pack-catalog/0007-acquisition-absence-receipts.sql"
);
const GENERATED_SOURCE_IDENTITIES_SQL: &str = include_str!(
    "../../../../migrations/semantic-pack-catalog/0008-generated-source-identities.sql"
);
const GENERATED_CACHE_EPOCHS_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0009-generated-cache-epochs.sql");
const SHARD_VALIDATION_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0010-shard-validation.sql");
const NATIVE_COMPATIBILITY_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0011-native-compatibility.sql");

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
    let mut connection = {
        let _scope = crate::profiling::scope("semantic_pack.catalog.sqlite_open");
        Connection::open_with_flags(&path, flags)
            .map_err(|error| CatalogError::sqlite("open catalog", error))?
    };
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
    {
        let _scope = crate::profiling::scope("semantic_pack.catalog.configure");
        match mode {
            CatalogOpenMode::ReadWrite => configure_writer(&mut connection)?,
            CatalogOpenMode::ReadOnly => configure_reader(&connection)?,
        }
    }
    {
        let _scope = crate::profiling::scope("semantic_pack.catalog.migrate");
        migrate(&mut connection, mode)?;
    }
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
    migrate_legacy_catalog_versions(connection)?;
    migrate_native_compatibility(connection)
}

fn migrate_legacy_catalog_versions(connection: &mut Connection) -> Result<(), CatalogError> {
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
    if locked_version >= CURRENT_CATALOG_VERSION {
        return transaction
            .commit()
            .map_err(|error| CatalogError::sqlite("commit catalog migration", error));
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
    if locked_version <= 6 {
        transaction
            .execute_batch(ACQUISITION_ABSENCE_RECEIPTS_SQL)
            .map_err(|error| {
                CatalogError::sqlite("apply acquisition-absence-receipt migration", error)
            })?;
    }
    if locked_version <= 7 {
        transaction
            .execute_batch(GENERATED_SOURCE_IDENTITIES_SQL)
            .map_err(|error| {
                CatalogError::sqlite("apply generated-source-identity migration", error)
            })?;
    }
    if locked_version <= 8 {
        transaction
            .execute_batch(GENERATED_CACHE_EPOCHS_SQL)
            .map_err(|error| {
                CatalogError::sqlite("apply generated-cache-epoch migration", error)
            })?;
        let current_keys = {
            let mut statement = transaction.prepare(
                "SELECT production_digest, input_digest, producer_name, producer_version, schema_version
                 FROM catalog_generated_productions"
            ).map_err(|error| CatalogError::sqlite("prepare legacy production epochs", error))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u32>(4)?,
                    ))
                })
                .map_err(|error| CatalogError::sqlite("read legacy production epochs", error))?;
            let mut current_keys = Vec::new();
            for row in rows {
                let (digest, input, producer, version, schema) = row.map_err(|error| {
                    CatalogError::sqlite("decode legacy production epoch", error)
                })?;
                if digest == super::generated_production_digest(&input, &producer, &version, schema)
                {
                    current_keys.push(digest);
                }
            }
            current_keys
        };
        for digest in current_keys {
            transaction
                .execute(
                    "UPDATE catalog_generated_productions SET generated_cache_version = ?1
                 WHERE production_digest = ?2",
                    rusqlite::params![super::GENERATED_PRODUCTION_CACHE_VERSION, digest],
                )
                .map_err(|error| {
                    CatalogError::sqlite("retain verified current production epoch", error)
                })?;
        }
    }
    if locked_version <= 9 {
        transaction
            .execute_batch(SHARD_VALIDATION_SQL)
            .map_err(|error| CatalogError::sqlite("apply shard-validation migration", error))?;
    }
    transaction
        .pragma_update(
            None,
            "user_version",
            PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION,
        )
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 10", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration", error))
}

fn migrate_native_compatibility(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 11", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version == CURRENT_CATALOG_VERSION {
        return Ok(());
    }
    if version != PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 11"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 11", error)
        })?;
    let migration_result = migrate_native_compatibility_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 11", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 11 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_native_compatibility_transaction(
    connection: &mut Connection,
) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 11", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 11", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version == CURRENT_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 11", error)
        });
    }
    if locked_version != PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 11"
        )));
    }

    transaction
        .execute_batch(NATIVE_COMPATIBILITY_SQL)
        .map_err(|error| {
            CatalogError::sqlite("apply native-compatibility catalog migration", error)
        })?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 11 foreign-key check", error)
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|error| CatalogError::sqlite("run migration 11 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 11 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 11 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", CURRENT_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 11", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 11", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::TempDir;

    #[derive(Debug, PartialEq)]
    struct CatalogPackRow {
        manifest_digest: String,
        semantic_digest: String,
        manifest_bytes: Vec<u8>,
        schema_version: u32,
        bifrost_compatibility: String,
        provenance_json: Vec<u8>,
        state: String,
        installed_at: i64,
        verified_at: i64,
        last_used_at: i64,
    }

    fn catalog_pack_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CatalogPackRow> {
        Ok(CatalogPackRow {
            manifest_digest: row.get(0)?,
            semantic_digest: row.get(1)?,
            manifest_bytes: row.get(2)?,
            schema_version: row.get(3)?,
            bifrost_compatibility: row.get(4)?,
            provenance_json: row.get(5)?,
            state: row.get(6)?,
            installed_at: row.get(7)?,
            verified_at: row.get(8)?,
            last_used_at: row.get(9)?,
        })
    }

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

    fn create_schema_10(connection: &mut Connection) {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 BEGIN IMMEDIATE;",
            )
            .unwrap();
        connection.execute_batch(BASELINE_SQL).unwrap();
        connection.execute_batch(LIFECYCLE_SQL).unwrap();
        connection.execute_batch(PROCEDURE_SUMMARIES_SQL).unwrap();
        connection.execute_batch(GENERATED_PRODUCTIONS_SQL).unwrap();
        connection.execute_batch(EXTRACTION_GAPS_SQL).unwrap();
        connection
            .execute_batch(EXTRACTION_SOURCE_ENTRIES_SQL)
            .unwrap();
        connection
            .execute_batch(ACQUISITION_ABSENCE_RECEIPTS_SQL)
            .unwrap();
        connection
            .execute_batch(GENERATED_SOURCE_IDENTITIES_SQL)
            .unwrap();
        connection
            .execute_batch(GENERATED_CACHE_EPOCHS_SQL)
            .unwrap();
        connection.execute_batch(SHARD_VALIDATION_SQL).unwrap();
        connection
            .pragma_update(
                None,
                "user_version",
                PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION,
            )
            .unwrap();
        connection.execute_batch("COMMIT;").unwrap();
    }

    fn insert_legacy_pack(connection: &Connection) {
        let manifest_digest = "a".repeat(64);
        let production_digest = "c".repeat(64);
        connection
            .execute(
                "INSERT INTO catalog_packs(
                   manifest_digest, semantic_digest, manifest_bytes, schema_version,
                   pack_id, pack_version, producer_name, producer_version, language,
                   ecosystem, bifrost_compatibility, provenance_json, license,
                   completeness, state, installed_at, verified_at, last_used_at
                 ) VALUES(?1, ?2, ?3, 2, 'fixture', '1.2.3', 'fixture-producer',
                   '4.5.6', 'java', 'jvm', '>=0.8.0, <1.0.0', ?4, 'Apache-2.0',
                   'partial', 'verified', 11, 12, 13)",
                params![
                    manifest_digest,
                    "b".repeat(64),
                    b"exact historical manifest bytes".as_slice(),
                    b"{\"source\":\"historical\",\"revision\":\"v10\"}".as_slice(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO catalog_sources(manifest_digest, source_kind, source_id, installed_at)
                 VALUES(?1, 'generated', ?2, 14)",
                params![manifest_digest, format!("production:{production_digest}")],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO catalog_pins(manifest_digest, pin_id, created_at)
                 VALUES(?1, 'historical-pin', 15)",
                [&manifest_digest],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO catalog_generated_productions(
                   production_digest, input_digest, producer_name, producer_version,
                   schema_version, manifest_digest, created_at, generated_cache_version
                 ) VALUES(?1, ?2, 'fixture-producer', '4.5.6', 2, ?3, 16, 38)",
                params![production_digest, "d".repeat(64), manifest_digest],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO catalog_generated_source_identities(
                   source_identity, producer_name, producer_version, schema_version,
                   generated_cache_version, production_digest, created_at
                 ) VALUES(?1, 'fixture-producer', '4.5.6', 2, 38, ?2, 17)",
                params!["e".repeat(64), production_digest],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO catalog_quarantine(manifest_digest, reason, detail, detected_at)
                 VALUES(?1, 'historical-reason', 'historical-detail', 18)",
                [&manifest_digest],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE catalog_semantic_state SET mutation_epoch = 777 WHERE singleton = 1",
                [],
            )
            .unwrap();
    }

    fn schema_objects(connection: &Connection) -> Vec<(String, String, Option<String>)> {
        let mut statement = connection
            .prepare(
                "SELECT type, name, sql FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    fn table_rows(connection: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .unwrap();
        statement
            .query_map([], |row| {
                (0..row.as_ref().column_count())
                    .map(|index| row.get(index))
                    .collect()
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    #[test]
    fn migration_11_preserves_legacy_rows_and_matches_fresh_schema() {
        let mut migrated = Connection::open_in_memory().unwrap();
        create_schema_10(&mut migrated);
        insert_legacy_pack(&migrated);
        let expected_full_pack_row = table_rows(&migrated, "catalog_packs");
        let expected_child_rows: Vec<(&str, Vec<Vec<rusqlite::types::Value>>)> = [
            "catalog_sources",
            "catalog_pins",
            "catalog_generated_productions",
            "catalog_generated_source_identities",
            "catalog_quarantine",
            "catalog_semantic_state",
        ]
        .into_iter()
        .map(|table| (table, table_rows(&migrated, table)))
        .collect();
        let expected_pack: CatalogPackRow = migrated
            .query_row(
                "SELECT manifest_digest, semantic_digest, manifest_bytes, schema_version,
                            bifrost_compatibility, provenance_json, state, installed_at,
                            verified_at, last_used_at
                     FROM catalog_packs",
                [],
                catalog_pack_row,
            )
            .unwrap();
        let expected_sources: Vec<(String, String, String, i64)> = {
            let mut statement = migrated
                .prepare("SELECT * FROM catalog_sources ORDER BY manifest_digest")
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let expected_epoch: i64 = migrated
            .query_row(
                "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let expected_production: (String, String, i64, Option<i64>) = migrated
            .query_row(
                "SELECT production_digest, manifest_digest, created_at, generated_cache_version
                 FROM catalog_generated_productions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        migrate(&mut migrated, CatalogOpenMode::ReadWrite).unwrap();
        assert_eq!(
            migrated
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            CURRENT_CATALOG_VERSION
        );
        assert_eq!(
            migrated
                .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        let actual_pack: CatalogPackRow = migrated
            .query_row(
                "SELECT manifest_digest, semantic_digest, manifest_bytes, schema_version,
                            bifrost_compatibility, provenance_json, state, installed_at,
                            verified_at, last_used_at
                     FROM catalog_packs",
                [],
                catalog_pack_row,
            )
            .unwrap();
        assert_eq!(
            table_rows(&migrated, "catalog_packs"),
            expected_full_pack_row
        );
        assert_eq!(actual_pack, expected_pack);
        for (table, expected_rows) in expected_child_rows {
            assert_eq!(table_rows(&migrated, table), expected_rows, "{table}");
        }
        let actual_sources: Vec<(String, String, String, i64)> = {
            let mut statement = migrated
                .prepare("SELECT * FROM catalog_sources ORDER BY manifest_digest")
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(actual_sources, expected_sources);
        assert_eq!(
            migrated
                .query_row(
                    "SELECT production_digest, manifest_digest, created_at, generated_cache_version
                     FROM catalog_generated_productions",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap(),
            expected_production
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            expected_epoch
        );
        assert_eq!(
            migrated
                .query_row("SELECT count(*) FROM catalog_pins", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            migrated
                .query_row("SELECT count(*) FROM catalog_quarantine", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let foreign_key_violations: i64 = migrated
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_violations, 0);
        assert_eq!(
            migrated
                .query_row(
                    "SELECT count(*) FROM catalog_verified_generated_productions",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let foreign_key_target: String = migrated
            .query_row(
                "SELECT \"table\" FROM pragma_foreign_key_list('catalog_sources')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(foreign_key_target, "catalog_packs");

        let mut fresh = Connection::open_in_memory().unwrap();
        fresh.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        migrate(&mut fresh, CatalogOpenMode::ReadWrite).unwrap();
        assert_eq!(schema_objects(&migrated), schema_objects(&fresh));
    }

    #[test]
    fn failed_migration_rolls_back_and_restores_foreign_keys() {
        let mut connection = Connection::open_in_memory().unwrap();
        create_schema_10(&mut connection);
        insert_legacy_pack(&connection);
        connection
            .execute("UPDATE catalog_packs SET schema_version = 9", [])
            .unwrap();
        let old_objects = schema_objects(&connection);
        let old_pack_row = table_rows(&connection, "catalog_packs");
        let old_sources = table_rows(&connection, "catalog_sources");
        let old_pins = table_rows(&connection, "catalog_pins");
        let old_generated = table_rows(&connection, "catalog_generated_productions");
        let old_epoch: i64 = connection
            .query_row(
                "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(migrate(&mut connection, CatalogOpenMode::ReadWrite).is_err());

        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION
        );
        assert_eq!(
            connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(schema_objects(&connection), old_objects);
        assert_eq!(table_rows(&connection, "catalog_packs"), old_pack_row);
        assert_eq!(table_rows(&connection, "catalog_sources"), old_sources);
        assert_eq!(table_rows(&connection, "catalog_pins"), old_pins);
        assert_eq!(
            table_rows(&connection, "catalog_generated_productions"),
            old_generated
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            old_epoch
        );
    }

    #[test]
    fn migration_11_check_requires_legacy_gate_and_forbids_native_gate() {
        let mut connection = Connection::open_in_memory().unwrap();
        create_schema_10(&mut connection);
        migrate(&mut connection, CatalogOpenMode::ReadWrite).unwrap();

        let insert_pack = |digest: &str, schema_version: i64, compatibility: Option<&str>| {
            connection.execute(
                "INSERT INTO catalog_packs(
                   manifest_digest, semantic_digest, manifest_bytes, schema_version,
                   pack_id, pack_version, producer_name, producer_version, language,
                   ecosystem, bifrost_compatibility, provenance_json, license,
                   completeness, state, installed_at, verified_at
                 ) VALUES(?1, ?2, X'01', ?3, 'fixture', '1.0.0', 'producer', '1.0.0',
                   'java', 'jvm', ?4, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params![digest, "f".repeat(64), schema_version, compatibility],
            )
        };
        insert_pack(&"a".repeat(64), 2, Some(">=0.8.0"))
            .expect("valid legacy row with engine range");
        insert_pack(&"b".repeat(64), 8, None).expect("valid schema-8 row without engine range");
        assert!(insert_pack(&"c".repeat(64), 2, None).is_err());
        assert!(insert_pack(&"d".repeat(64), 8, Some("*")).is_err());
        assert!(insert_pack(&"e".repeat(64), 9, None).is_err());
    }

    #[test]
    fn read_only_old_and_too_new_catalog_errors_leave_database_bytes_unchanged() {
        for (version, expected_error) in [
            (
                10,
                CatalogError::ReadOnlySchema {
                    found: 10,
                    required: CURRENT_CATALOG_VERSION,
                },
            ),
            (
                12,
                CatalogError::CatalogTooNew {
                    found: 12,
                    supported: CURRENT_CATALOG_VERSION,
                },
            ),
        ] {
            let root = TempDir::new().unwrap();
            let path = root.path().join(CATALOG_DB_FILE_NAME);
            let root_path = std::fs::canonicalize(root.path()).unwrap();
            let connection = Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "user_version", version)
                .unwrap();
            drop(connection);
            let original_bytes = std::fs::read(&path).unwrap();
            let error = open(&root_path, CatalogOpenMode::ReadOnly).unwrap_err();
            match (error, expected_error) {
                (
                    CatalogError::ReadOnlySchema {
                        found: 10,
                        required: CURRENT_CATALOG_VERSION,
                    },
                    CatalogError::ReadOnlySchema { .. },
                ) => {}
                (
                    CatalogError::CatalogTooNew {
                        found: 12,
                        supported: CURRENT_CATALOG_VERSION,
                    },
                    CatalogError::CatalogTooNew { .. },
                ) => {}
                (error, expected) => panic!("expected {expected:?}, found {error:?}"),
            }
            assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
            let check = Connection::open(&path).unwrap();
            assert_eq!(
                check
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                version
            );
        }
    }
}
