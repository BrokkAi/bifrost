use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use crate::analyzer::semantic_model::catalog::CatalogError;

use crate::analyzer::semantic_model::catalog::CatalogOpenMode;

use brokk_bifrost_core::sqlite_template;

pub(in crate::analyzer::semantic_model::catalog) const CATALOG_DB_FILE_NAME: &str = "catalog.db";
pub(in crate::analyzer::semantic_model::catalog) const CURRENT_CATALOG_VERSION: i64 = 22;
const PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION: i64 = 10;
const NATIVE_COMPATIBILITY_CATALOG_VERSION: i64 = 11;
const UNKNOWN_TYPES_CATALOG_VERSION: i64 = 12;
const CALLABLE_VALUES_CATALOG_VERSION: i64 = 13;
const CALLABLE_VALUE_ROWS_CATALOG_VERSION: i64 = 14;
const STRUCTURED_FORMALS_CATALOG_VERSION: i64 = 15;
const SEMANTIC_MODEL_SCHEMA_CATALOG_VERSION: i64 = 16;
const EXACT_GO_SOURCE_ROWS_CATALOG_VERSION: i64 = 17;
const SEMANTIC_MODEL_SCHEMA_V14_CATALOG_VERSION: i64 = 18;
const SEMANTIC_MODEL_SCHEMA_V15_CATALOG_VERSION: i64 = 19;
const SEMANTIC_MODEL_SCHEMA_V16_CATALOG_VERSION: i64 = 20;
const SEMANTIC_MODEL_SCHEMA_V17_CATALOG_VERSION: i64 = 21;
const SEMANTIC_MODEL_SCHEMA_V18_CATALOG_VERSION: i64 = 22;
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
const UNKNOWN_TYPES_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0012-unknown-types.sql");
const CALLABLE_VALUES_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0013-callable-values.sql");
pub(in crate::analyzer::semantic_model::catalog) const CALLABLE_VALUE_ROWS_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0014-callable-value-rows.sql");
const STRUCTURED_FORMALS_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0015-structured-formals.sql");
const SEMANTIC_MODEL_SCHEMA_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0016-semantic-model-schema.sql");
pub(in crate::analyzer::semantic_model::catalog) const EXACT_GO_SOURCE_ROWS_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0017-exact-go-source-rows.sql");
const SEMANTIC_MODEL_SCHEMA_V14_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0018-semantic-model-schema-v14.sql");
const SEMANTIC_MODEL_SCHEMA_V15_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0019-semantic-model-schema-v15.sql");
const SEMANTIC_MODEL_SCHEMA_V16_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0020-semantic-model-schema-v16.sql");
const SEMANTIC_MODEL_SCHEMA_V17_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0021-semantic-model-schema-v17.sql");

const SEMANTIC_MODEL_SCHEMA_V18_SQL: &str =
    include_str!("../../../../migrations/semantic-pack-catalog/0022-semantic-model-schema-v18.sql");

/// This build's empty-catalog template. The migrations are the schema inputs:
/// on an empty catalog their Rust steps have no rows to change, so the SQL
/// alone decides the bytes.
static CATALOG_TEMPLATE: LazyLock<sqlite_template::Template> = LazyLock::new(|| {
    sqlite_template::Template::new(
        "semantic-pack-catalog",
        CURRENT_CATALOG_VERSION,
        &[
            BASELINE_SQL.as_bytes(),
            LIFECYCLE_SQL.as_bytes(),
            PROCEDURE_SUMMARIES_SQL.as_bytes(),
            GENERATED_PRODUCTIONS_SQL.as_bytes(),
            EXTRACTION_GAPS_SQL.as_bytes(),
            EXTRACTION_SOURCE_ENTRIES_SQL.as_bytes(),
            ACQUISITION_ABSENCE_RECEIPTS_SQL.as_bytes(),
            GENERATED_SOURCE_IDENTITIES_SQL.as_bytes(),
            GENERATED_CACHE_EPOCHS_SQL.as_bytes(),
            SHARD_VALIDATION_SQL.as_bytes(),
            NATIVE_COMPATIBILITY_SQL.as_bytes(),
            UNKNOWN_TYPES_SQL.as_bytes(),
            CALLABLE_VALUES_SQL.as_bytes(),
            CALLABLE_VALUE_ROWS_SQL.as_bytes(),
            STRUCTURED_FORMALS_SQL.as_bytes(),
            SEMANTIC_MODEL_SCHEMA_SQL.as_bytes(),
            EXACT_GO_SOURCE_ROWS_SQL.as_bytes(),
            SEMANTIC_MODEL_SCHEMA_V14_SQL.as_bytes(),
            SEMANTIC_MODEL_SCHEMA_V15_SQL.as_bytes(),
            SEMANTIC_MODEL_SCHEMA_V16_SQL.as_bytes(),
            SEMANTIC_MODEL_SCHEMA_V17_SQL.as_bytes(),
            SEMANTIC_MODEL_SCHEMA_V18_SQL.as_bytes(),
        ],
    )
});

#[doc(hidden)]
pub fn open(root: &Path, mode: CatalogOpenMode) -> Result<Connection, CatalogError> {
    // The catalog is the other database a Bifrost process can open first, and
    // the memory-statistics knob is only settable before the first connection.
    brokk_bifrost_core::cache_db::disable_sqlite_memory_statistics();
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
    if mode == CatalogOpenMode::ReadWrite {
        // A new catalog runs twenty-two migrations. Copy a template instead; see
        // `sqlite_template`. The caller holds the catalog's initialization
        // lock, so no other opener is creating this file.
        let _scope =
            brokk_bifrost_core::profiling::scope("semantic_pack.catalog.seed_from_template");
        let template_dir = sqlite_template::template_dir();
        sqlite_template::seed_missing_database(
            &path,
            template_dir.as_deref(),
            &CATALOG_TEMPLATE,
            build_fresh_catalog,
        )?;
    }
    let mut connection = {
        let _scope = brokk_bifrost_core::profiling::scope("semantic_pack.catalog.sqlite_open");
        Connection::open_with_flags(&path, flags)
            .map_err(|error| CatalogError::sqlite("open catalog", error))?
    };
    if mode == CatalogOpenMode::ReadWrite {
        connection.set_transaction_behavior(TransactionBehavior::Immediate);
    }
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
        let _scope = brokk_bifrost_core::profiling::scope("semantic_pack.catalog.configure");
        match mode {
            CatalogOpenMode::ReadWrite => configure_writer(&mut connection)?,
            CatalogOpenMode::ReadOnly => configure_reader(&connection)?,
        }
    }
    {
        let _scope = brokk_bifrost_core::profiling::scope("semantic_pack.catalog.migrate");
        migrate(&mut connection, mode)?;
    }
    Ok(connection)
}

/// Create an empty current-schema catalog at `path` through the ordinary path.
fn build_fresh_catalog(path: &Path) -> Result<(), CatalogError> {
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| CatalogError::sqlite("open catalog template", error))?;
    connection.set_transaction_behavior(TransactionBehavior::Immediate);
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|error| CatalogError::sqlite("configure busy timeout", error))?;
    configure_writer(&mut connection)?;
    migrate(&mut connection, CatalogOpenMode::ReadWrite)?;
    // Closing the only connection checkpoints the WAL into the main file and
    // removes the WAL, so the main file alone is the complete catalog.
    connection
        .close()
        .map_err(|(_, error)| CatalogError::sqlite("close catalog template", error))
}

fn configure_writer(connection: &mut Connection) -> Result<(), CatalogError> {
    ensure_wal_journal_mode(connection)?;
    connection
        .pragma_update(
            None,
            "synchronous",
            brokk_bifrost_core::cache_db::sqlite_synchronous(),
        )
        .map_err(|error| CatalogError::sqlite("configure catalog synchronous writes", error))?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA recursive_triggers = ON;
             PRAGMA temp_store = MEMORY;",
        )
        .map_err(|error| CatalogError::sqlite("configure catalog writer", error))
}

fn ensure_wal_journal_mode(connection: &Connection) -> Result<(), CatalogError> {
    let updated =
        retry_initialization(|| brokk_bifrost_core::cache_db::set_wal_journal_mode(connection))
            .map_err(|error| CatalogError::sqlite("configure catalog journal mode", error))?;
    if !updated.eq_ignore_ascii_case("wal") {
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
    if version >= CURRENT_CATALOG_VERSION {
        return Ok(());
    }
    if mode == CatalogOpenMode::ReadOnly {
        return Err(CatalogError::ReadOnlySchema {
            found: version,
            required: CURRENT_CATALOG_VERSION,
        });
    }
    migrate_legacy_catalog_versions(connection)?;
    migrate_native_compatibility(connection)?;
    migrate_unknown_types(connection)?;
    migrate_callable_values(connection)?;
    migrate_callable_value_rows(connection)?;
    migrate_structured_formals(connection)?;
    migrate_semantic_model_schema(connection)?;
    migrate_exact_go_source_rows(connection)?;
    migrate_semantic_model_schema_v14(connection)?;
    migrate_semantic_model_schema_v15(connection)?;
    migrate_semantic_model_schema_v16(connection)?;
    migrate_semantic_model_schema_v17(connection)?;
    migrate_semantic_model_schema_v18(connection)
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
    if locked_version >= PRE_NATIVE_COMPATIBILITY_CATALOG_VERSION {
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
                if digest
                    == crate::analyzer::semantic_model::catalog::generated_production_digest(
                        &input, &producer, &version, schema,
                    )
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
                    rusqlite::params![crate::analyzer::semantic_model::catalog::GENERATED_PRODUCTION_CACHE_VERSION, digest],
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
    if version >= NATIVE_COMPATIBILITY_CATALOG_VERSION {
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
    if locked_version >= NATIVE_COMPATIBILITY_CATALOG_VERSION {
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
        .pragma_update(None, "user_version", NATIVE_COMPATIBILITY_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 11", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 11", error))
}

fn migrate_unknown_types(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 12", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= UNKNOWN_TYPES_CATALOG_VERSION {
        return Ok(());
    }
    if version != NATIVE_COMPATIBILITY_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 12"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 12", error)
        })?;
    let migration_result = migrate_unknown_types_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 12", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 12 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_unknown_types_transaction(connection: &mut Connection) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 12", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 12", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= UNKNOWN_TYPES_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 12", error)
        });
    }
    if locked_version != NATIVE_COMPATIBILITY_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 12"
        )));
    }

    transaction
        .execute_batch(UNKNOWN_TYPES_SQL)
        .map_err(|error| CatalogError::sqlite("apply unknown-types catalog migration", error))?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 12 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 12 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 12 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 12 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", UNKNOWN_TYPES_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 12", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 12", error))
}

fn migrate_callable_values(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 13", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= CALLABLE_VALUES_CATALOG_VERSION {
        return Ok(());
    }
    if version != UNKNOWN_TYPES_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 13"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 13", error)
        })?;
    let migration_result = migrate_callable_values_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 13", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 13 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_callable_values_transaction(connection: &mut Connection) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 13", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 13", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= CALLABLE_VALUES_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 13", error)
        });
    }
    if locked_version != UNKNOWN_TYPES_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 13"
        )));
    }

    transaction
        .execute_batch(CALLABLE_VALUES_SQL)
        .map_err(|error| CatalogError::sqlite("apply callable-values catalog migration", error))?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 13 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 13 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 13 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 13 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", CALLABLE_VALUES_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 13", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 13", error))
}

fn migrate_callable_value_rows(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 14", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= CALLABLE_VALUE_ROWS_CATALOG_VERSION {
        return Ok(());
    }
    if version != CALLABLE_VALUES_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 14"
        )));
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 14", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 14", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= CALLABLE_VALUE_ROWS_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 14", error)
        });
    }
    if locked_version != CALLABLE_VALUES_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 14"
        )));
    }

    transaction
        .execute_batch(CALLABLE_VALUE_ROWS_SQL)
        .map_err(|error| CatalogError::sqlite("apply callable-value-row migration", error))?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 14 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 14 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 14 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 14 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", CALLABLE_VALUE_ROWS_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 14", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 14", error))
}

fn migrate_structured_formals(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 15", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= STRUCTURED_FORMALS_CATALOG_VERSION {
        return Ok(());
    }
    if version != CALLABLE_VALUE_ROWS_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 15"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 15", error)
        })?;
    let migration_result = migrate_structured_formals_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 15", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 15 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_structured_formals_transaction(connection: &mut Connection) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 15", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 15", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= STRUCTURED_FORMALS_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 15", error)
        });
    }
    if locked_version != CALLABLE_VALUE_ROWS_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 15"
        )));
    }

    transaction
        .execute_batch(STRUCTURED_FORMALS_SQL)
        .map_err(|error| {
            CatalogError::sqlite("apply structured-formals catalog migration", error)
        })?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 15 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 15 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 15 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 15 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", STRUCTURED_FORMALS_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 15", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 15", error))
}

fn migrate_semantic_model_schema(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 16", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= SEMANTIC_MODEL_SCHEMA_CATALOG_VERSION {
        return Ok(());
    }
    if version != STRUCTURED_FORMALS_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 16"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 16", error)
        })?;
    let migration_result = migrate_semantic_model_schema_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 16", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 16 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_semantic_model_schema_transaction(
    connection: &mut Connection,
) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 16", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 16", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= SEMANTIC_MODEL_SCHEMA_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 16", error)
        });
    }
    if locked_version != STRUCTURED_FORMALS_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 16"
        )));
    }

    transaction
        .execute_batch(SEMANTIC_MODEL_SCHEMA_SQL)
        .map_err(|error| {
            CatalogError::sqlite("apply semantic-model-schema catalog migration", error)
        })?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 16 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 16 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 16 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 16 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", SEMANTIC_MODEL_SCHEMA_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 16", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 16", error))
}

fn migrate_exact_go_source_rows(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 17", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= EXACT_GO_SOURCE_ROWS_CATALOG_VERSION {
        return Ok(());
    }
    if version != SEMANTIC_MODEL_SCHEMA_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 17"
        )));
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 17", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 17", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= EXACT_GO_SOURCE_ROWS_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 17", error)
        });
    }
    if locked_version != SEMANTIC_MODEL_SCHEMA_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 17"
        )));
    }

    transaction
        .execute_batch(EXACT_GO_SOURCE_ROWS_SQL)
        .map_err(|error| CatalogError::sqlite("apply exact Go source-row migration", error))?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 17 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 17 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 17 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 17 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", EXACT_GO_SOURCE_ROWS_CATALOG_VERSION)
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 17", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 17", error))
}

fn migrate_semantic_model_schema_v14(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 18", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= SEMANTIC_MODEL_SCHEMA_V14_CATALOG_VERSION {
        return Ok(());
    }
    if version != EXACT_GO_SOURCE_ROWS_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 18"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 18", error)
        })?;
    let migration_result = migrate_semantic_model_schema_v14_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 18", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 18 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_semantic_model_schema_v14_transaction(
    connection: &mut Connection,
) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 18", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 18", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= SEMANTIC_MODEL_SCHEMA_V14_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 18", error)
        });
    }
    if locked_version != EXACT_GO_SOURCE_ROWS_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 18"
        )));
    }

    transaction
        .execute_batch(SEMANTIC_MODEL_SCHEMA_V14_SQL)
        .map_err(|error| {
            CatalogError::sqlite("apply semantic-model-schema-v14 catalog migration", error)
        })?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 18 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 18 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 18 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 18 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(
            None,
            "user_version",
            SEMANTIC_MODEL_SCHEMA_V14_CATALOG_VERSION,
        )
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 18", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 18", error))
}

fn migrate_semantic_model_schema_v15(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 19", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= SEMANTIC_MODEL_SCHEMA_V15_CATALOG_VERSION {
        return Ok(());
    }
    if version != SEMANTIC_MODEL_SCHEMA_V14_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 19"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 19", error)
        })?;
    let migration_result = migrate_semantic_model_schema_v15_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 19", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 19 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_semantic_model_schema_v15_transaction(
    connection: &mut Connection,
) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 19", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 19", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= SEMANTIC_MODEL_SCHEMA_V15_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 19", error)
        });
    }
    if locked_version != SEMANTIC_MODEL_SCHEMA_V14_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 19"
        )));
    }

    transaction
        .execute_batch(SEMANTIC_MODEL_SCHEMA_V15_SQL)
        .map_err(|error| {
            CatalogError::sqlite("apply semantic-model-schema-v15 catalog migration", error)
        })?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 19 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 19 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 19 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 19 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(
            None,
            "user_version",
            SEMANTIC_MODEL_SCHEMA_V15_CATALOG_VERSION,
        )
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 19", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 19", error))
}

fn migrate_semantic_model_schema_v16(connection: &mut Connection) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("read catalog schema version before migration 20", error)
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= SEMANTIC_MODEL_SCHEMA_V16_CATALOG_VERSION {
        return Ok(());
    }
    if version != SEMANTIC_MODEL_SCHEMA_V15_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before migration 20"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite("disable catalog foreign keys for migration 20", error)
        })?;
    let migration_result = migrate_semantic_model_schema_v16_transaction(connection);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite("restore catalog foreign keys after migration 20", error)
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog migration 20 failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_semantic_model_schema_v16_transaction(
    connection: &mut Connection,
) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog migration 20", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite("recheck catalog schema before migration 20", error)
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= SEMANTIC_MODEL_SCHEMA_V16_CATALOG_VERSION {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog migration 20", error)
        });
    }
    if locked_version != SEMANTIC_MODEL_SCHEMA_V15_CATALOG_VERSION {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before migration 20"
        )));
    }

    transaction
        .execute_batch(SEMANTIC_MODEL_SCHEMA_V16_SQL)
        .map_err(|error| {
            CatalogError::sqlite("apply semantic-model-schema-v16 catalog migration", error)
        })?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare migration 20 foreign-key check", error)
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
            .map_err(|error| CatalogError::sqlite("run migration 20 foreign-key check", error))?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite("read migration 20 foreign-key violation", error)
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog migration 20 found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(
            None,
            "user_version",
            SEMANTIC_MODEL_SCHEMA_V16_CATALOG_VERSION,
        )
        .map_err(|error| CatalogError::sqlite("publish catalog schema version 20", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog migration 20", error))
}

fn migrate_semantic_model_schema_v17(connection: &mut Connection) -> Result<(), CatalogError> {
    migrate_manifest_schema(
        connection,
        SEMANTIC_MODEL_SCHEMA_V17_CATALOG_VERSION,
        SEMANTIC_MODEL_SCHEMA_V17_SQL,
    )
}

fn migrate_semantic_model_schema_v18(connection: &mut Connection) -> Result<(), CatalogError> {
    migrate_manifest_schema(
        connection,
        SEMANTIC_MODEL_SCHEMA_V18_CATALOG_VERSION,
        SEMANTIC_MODEL_SCHEMA_V18_SQL,
    )
}

fn migrate_manifest_schema(
    connection: &mut Connection,
    target_version: i64,
    sql: &str,
) -> Result<(), CatalogError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite(
                "read catalog schema version before manifest-schema migration",
                error,
            )
        })?;
    if version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if version >= target_version {
        return Ok(());
    }
    if version != (target_version - 1) {
        return Err(CatalogError::Integrity(format!(
            "catalog schema reached unexpected version {version} before manifest-schema migration {target_version}"
        )));
    }

    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(|error| {
            CatalogError::sqlite(
                "disable catalog foreign keys for manifest-schema migration",
                error,
            )
        })?;
    let migration_result = migrate_manifest_schema_transaction(connection, target_version, sql);
    let foreign_keys_result = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| {
            CatalogError::sqlite(
                "restore catalog foreign keys after manifest-schema migration",
                error,
            )
        });
    match (migration_result, foreign_keys_result) {
        (Err(migration_error), Ok(())) => Err(migration_error),
        (Err(migration_error), Err(foreign_keys_error)) => Err(CatalogError::Integrity(format!(
            "catalog manifest-schema migration {target_version} failed: {migration_error}; restoring foreign-key enforcement failed: {foreign_keys_error}"
        ))),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn migrate_manifest_schema_transaction(
    connection: &mut Connection,
    target_version: i64,
    sql: &str,
) -> Result<(), CatalogError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| CatalogError::sqlite("begin catalog manifest-schema migration", error))?;
    let locked_version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| {
            CatalogError::sqlite(
                "recheck catalog schema before manifest-schema migration",
                error,
            )
        })?;
    if locked_version > CURRENT_CATALOG_VERSION {
        return Err(CatalogError::CatalogTooNew {
            found: locked_version,
            supported: CURRENT_CATALOG_VERSION,
        });
    }
    if locked_version >= target_version {
        return transaction.commit().map_err(|error| {
            CatalogError::sqlite("commit concurrent catalog manifest-schema migration", error)
        });
    }
    if locked_version != (target_version - 1) {
        return Err(CatalogError::Integrity(format!(
            "catalog schema changed to unexpected version {locked_version} before manifest-schema migration {target_version}"
        )));
    }

    transaction
        .execute_batch(sql)
        .map_err(|error| CatalogError::sqlite("apply manifest-schema catalog migration", error))?;
    let foreign_key_violations = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CatalogError::sqlite("prepare manifest-schema migration foreign-key check", error)
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
            .map_err(|error| {
                CatalogError::sqlite("run manifest-schema migration foreign-key check", error)
            })?;
        let mut violations = Vec::new();
        for row in rows {
            violations.push(row.map_err(|error| {
                CatalogError::sqlite(
                    "read manifest-schema migration foreign-key violation",
                    error,
                )
            })?);
        }
        violations
    };
    if !foreign_key_violations.is_empty() {
        return Err(CatalogError::Integrity(format!(
            "catalog manifest-schema migration {target_version} found foreign-key violations: {foreign_key_violations:?}"
        )));
    }
    transaction
        .pragma_update(None, "user_version", target_version)
        .map_err(|error| CatalogError::sqlite("publish manifest-schema catalog version", error))?;
    transaction
        .commit()
        .map_err(|error| CatalogError::sqlite("commit catalog manifest-schema migration", error))
}

#[cfg(test)]
mod tests {

    use crate::analyzer::semantic_model::catalog::db::*;
    use brokk_bifrost_test_macros::hardwon;
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
    fn a_catalog_seeded_from_the_template_matches_a_catalog_built_by_migration() {
        let temp = TempDir::new().unwrap();
        // The template builders open with SQLITE_OPEN_NOFOLLOW, which rejects a
        // symlink anywhere in the path, and production passes canonical paths.
        // macOS temp directories live under /var -> /private/var (#4604).
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let template_dir = root.join("templates");
        let reference = root.join("reference.db");
        std::fs::File::create(&reference).unwrap();
        build_fresh_catalog(&reference).unwrap();

        // The first catalog builds and publishes the template; the second copies it.
        let first = root.join("first.db");
        let second = root.join("second.db");
        for seeded in [&first, &second] {
            assert!(
                sqlite_template::seed_missing_database(
                    seeded,
                    Some(&template_dir),
                    &CATALOG_TEMPLATE,
                    build_fresh_catalog,
                )
                .unwrap()
            );
        }
        let template_entries = std::fs::read_dir(&template_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            template_entries,
            vec![CATALOG_TEMPLATE.file_name().to_owned()]
        );

        let describe = |path: &Path| {
            let connection = Connection::open(path).unwrap();
            let version: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            let journal_mode: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            let mut statement = connection
                .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
                .unwrap();
            let objects = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let rows = objects
                .iter()
                .filter(|(object_type, name, _)| {
                    object_type == "table" && !name.starts_with("sqlite_")
                })
                .map(|(_, name, _)| {
                    connection
                        .query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |row| {
                            row.get::<_, i64>(0)
                        })
                        .unwrap()
                })
                .collect::<Vec<_>>();
            (version, journal_mode, objects, rows)
        };
        let expected = describe(&reference);
        assert_eq!(expected.0, CURRENT_CATALOG_VERSION);
        for seeded in [&first, &second] {
            assert_eq!(describe(seeded), expected, "{}", seeded.display());
        }
    }

    #[test]
    #[hardwon("#3815: schema-aware pack admission migration broke catalog compatibility")]
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
    #[hardwon("#3815: failed catalog migration left partial schema changes behind")]
    fn failed_migration_rolls_back_and_restores_foreign_keys() {
        let mut connection = Connection::open_in_memory().unwrap();
        create_schema_10(&mut connection);
        insert_legacy_pack(&connection);
        connection
            .execute("UPDATE catalog_packs SET schema_version = 10", [])
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
    #[hardwon("#3815: native packs were admitted under the wrong schema gate")]
    fn migration_11_check_requires_legacy_gate_and_forbids_native_gate() {
        let mut connection = Connection::open_in_memory().unwrap();
        create_schema_10(&mut connection);
        migrate_native_compatibility(&mut connection).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            NATIVE_COMPATIBILITY_CATALOG_VERSION
        );

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
    fn migration_12_preserves_catalog_rows_and_admits_schema_nine() {
        let mut connection = Connection::open_in_memory().unwrap();
        create_schema_10(&mut connection);
        insert_legacy_pack(&connection);
        migrate_native_compatibility(&mut connection).unwrap();
        assert!(matches!(
            migrate(&mut connection, CatalogOpenMode::ReadOnly),
            Err(CatalogError::ReadOnlySchema {
                found: NATIVE_COMPATIBILITY_CATALOG_VERSION,
                required: CURRENT_CATALOG_VERSION,
            })
        ));

        let schema_eight_digest = "9".repeat(64);
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 8, 'schema-eight', '1.0.0', 'producer', '1.0.0',
               'java', 'jvm', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params![schema_eight_digest, "b".repeat(64)],
            )
            .unwrap();
        let initial_epoch: i64 = connection
            .query_row(
                "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let pack_rows = table_rows(&connection, "catalog_packs");
        let source_rows = table_rows(&connection, "catalog_sources");
        let pin_rows = table_rows(&connection, "catalog_pins");
        let generated_rows = table_rows(&connection, "catalog_generated_productions");
        let semantic_epoch = table_rows(&connection, "catalog_semantic_state");
        let child_rows: Vec<(&str, Vec<Vec<rusqlite::types::Value>>)> = [
            "catalog_pack_shards",
            "catalog_sources",
            "catalog_pins",
            "catalog_generated_source_identities",
            "catalog_shard_validations",
            "catalog_quarantine",
        ]
        .into_iter()
        .map(|table| (table, table_rows(&connection, table)))
        .collect();
        let pack_indexes_and_triggers = {
            let mut statement = connection
                .prepare(
                    "SELECT type, name, sql FROM sqlite_schema
                     WHERE tbl_name = 'catalog_packs' AND type IN ('index', 'trigger')
                     ORDER BY type, name",
                )
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let generated_view_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'view' AND name = 'catalog_verified_generated_productions'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        migrate(&mut connection, CatalogOpenMode::ReadWrite).unwrap();

        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            CURRENT_CATALOG_VERSION
        );
        assert!(table_rows(&connection, "catalog_exact_go_source_sets").is_empty());
        assert!(table_rows(&connection, "catalog_exact_go_source_files").is_empty());
        assert!(table_rows(&connection, "catalog_exact_go_packages").is_empty());
        assert!(table_rows(&connection, "catalog_exact_go_package_files").is_empty());
        assert_eq!(table_rows(&connection, "catalog_packs"), pack_rows);
        assert_eq!(table_rows(&connection, "catalog_sources"), source_rows);
        assert_eq!(table_rows(&connection, "catalog_pins"), pin_rows);
        assert_eq!(
            table_rows(&connection, "catalog_generated_productions"),
            generated_rows
        );
        assert_eq!(
            table_rows(&connection, "catalog_semantic_state"),
            semantic_epoch,
            "the parent-table rebuild must not fire mutation triggers"
        );
        for (table, rows) in child_rows {
            assert_eq!(table_rows(&connection, table), rows, "{table}");
        }
        let actual_pack_indexes_and_triggers = {
            let mut statement = connection
                .prepare(
                    "SELECT type, name, sql FROM sqlite_schema
                     WHERE tbl_name = 'catalog_packs' AND type IN ('index', 'trigger')
                     ORDER BY type, name",
                )
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(actual_pack_indexes_and_triggers, pack_indexes_and_triggers);
        assert_eq!(
            connection
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'view' AND name = 'catalog_verified_generated_productions'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            generated_view_sql
        );
        assert_eq!(
            connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );

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
        insert_pack(&"c".repeat(64), 9, None).expect("schema 9 omits the engine gate");
        assert!(insert_pack(&"d".repeat(64), 9, Some("*")).is_err());
        assert!(insert_pack(&"e".repeat(64), 2, None).is_err());
        assert!(insert_pack(&"f".repeat(64), 8, Some("*")).is_err());
        assert!(
            initial_epoch
                < connection
                    .query_row(
                        "SELECT mutation_epoch FROM catalog_semantic_state WHERE singleton = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap()
        );
    }

    #[test]
    fn migrations_13_through_22_preserve_catalog_rows_and_defer_old_shards_to_demand() {
        let mut connection = Connection::open_in_memory().unwrap();
        create_schema_10(&mut connection);
        insert_legacy_pack(&connection);
        migrate_native_compatibility(&mut connection).unwrap();
        migrate_unknown_types(&mut connection).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            UNKNOWN_TYPES_CATALOG_VERSION
        );

        let pack_rows = table_rows(&connection, "catalog_packs");
        let source_rows = table_rows(&connection, "catalog_sources");
        let generated_rows = table_rows(&connection, "catalog_generated_productions");
        let identity_rows = table_rows(&connection, "catalog_generated_source_identities");
        let quarantine_rows = table_rows(&connection, "catalog_quarantine");
        let epoch_rows = table_rows(&connection, "catalog_semantic_state");

        migrate_callable_values(&mut connection).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            CALLABLE_VALUES_CATALOG_VERSION
        );
        migrate_callable_value_rows(&mut connection).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            CALLABLE_VALUE_ROWS_CATALOG_VERSION
        );
        migrate_structured_formals(&mut connection).unwrap();

        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            STRUCTURED_FORMALS_CATALOG_VERSION
        );
        assert_eq!(table_rows(&connection, "catalog_packs"), pack_rows);
        assert_eq!(table_rows(&connection, "catalog_sources"), source_rows);
        assert_eq!(
            table_rows(&connection, "catalog_generated_productions"),
            generated_rows
        );
        assert_eq!(
            table_rows(&connection, "catalog_generated_source_identities"),
            identity_rows
        );
        assert_eq!(
            table_rows(&connection, "catalog_quarantine"),
            quarantine_rows
        );
        assert_eq!(
            table_rows(&connection, "catalog_semantic_state"),
            epoch_rows,
            "the parent-table rebuild must not fire mutation triggers"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM catalog_callable_values_indexed_shards",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "schema migration leaves old shards unindexed until an exact demand reconciles them"
        );

        let rows_after_callable_values = table_rows(&connection, "catalog_packs");
        let epoch_after_callable_values = table_rows(&connection, "catalog_semantic_state");
        migrate_semantic_model_schema(&mut connection).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            SEMANTIC_MODEL_SCHEMA_CATALOG_VERSION
        );
        migrate_exact_go_source_rows(&mut connection).unwrap();
        migrate_semantic_model_schema_v14(&mut connection).unwrap();
        migrate_semantic_model_schema_v15(&mut connection).unwrap();
        migrate_semantic_model_schema_v16(&mut connection).unwrap();
        migrate_semantic_model_schema_v17(&mut connection).unwrap();
        migrate_semantic_model_schema_v18(&mut connection).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            CURRENT_CATALOG_VERSION
        );
        assert_eq!(
            table_rows(&connection, "catalog_packs"),
            rows_after_callable_values
        );
        assert_eq!(
            table_rows(&connection, "catalog_semantic_state"),
            epoch_after_callable_values,
            "the schema-compatibility rebuild must not fire mutation triggers"
        );

        let schema_ten_digest = "9".repeat(64);
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 10, 'schema-ten', '1.0.0', 'producer', '1.0.0',
               'go', 'go', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params![schema_ten_digest, "b".repeat(64)],
            )
            .expect("schema 10 is admitted after migration 15");
        assert!(
            connection
                .execute(
                    "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 10, 'schema-ten-invalid', '1.0.0', 'producer', '1.0.0',
               'go', 'go', '*', X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                    params!["8".repeat(64), "c".repeat(64)],
                )
                .is_err()
        );
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 11, 'schema-eleven', '1.0.0', 'producer', '1.0.0',
               'go', 'go', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params!["4".repeat(64), "3".repeat(64)],
            )
            .expect("schema 11 remains supported after migration 18");
        let schema_twelve_digest = "7".repeat(64);
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 12, 'schema-twelve', '1.0.0', 'producer', '1.0.0',
               'go', 'go', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params![schema_twelve_digest, "f".repeat(64)],
            )
            .expect("schema 12 is admitted after migration 18");
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 13, 'schema-thirteen', '1.0.0', 'producer', '1.0.0',
               'go', 'go', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params!["5".repeat(64), "2".repeat(64)],
            )
            .expect("schema 13 is admitted after migration 18");
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 14, 'schema-fourteen', '1.0.0', 'producer', '1.0.0',
               'go', 'go', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params!["6".repeat(64), "d".repeat(64)],
            )
            .expect("schema 14 remains admitted after migration 19");
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
            ) VALUES(?1, ?2, X'01', 15, 'schema-fifteen', '1.0.0', 'producer', '1.0.0',
               'python', 'pypi', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params!["1".repeat(64), "0".repeat(64)],
            )
            .expect("schema 15 is admitted after migration 19");
        connection
            .execute(
                "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 16, 'schema-sixteen', '1.0.0', 'producer', '1.0.0',
               'python', 'pypi', NULL, X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                params!["2".repeat(64), "9".repeat(64)],
            )
            .expect("schema 16 is admitted after migration 20");
        connection
            .execute(
                "INSERT INTO catalog_packs(
                manifest_digest, semantic_digest, manifest_bytes, schema_version,
                pack_id, pack_version, producer_name, producer_version, language,
                ecosystem, bifrost_compatibility, provenance_json, license,
                completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 17, 'schema-seventeen', '1.0.0', 'producer', '1.0.0',
                'python', 'python', NULL, X'7B7D', 'Apache-2.0', 'partial', 'verified', 1, 1)",
                params!["17".repeat(32), "6".repeat(64)],
            )
            .expect("schema 17 is admitted after migration 21");
        connection.execute(
            "INSERT INTO catalog_packs(manifest_digest, semantic_digest, manifest_bytes, schema_version,
              pack_id, pack_version, producer_name, producer_version, language, ecosystem,
              bifrost_compatibility, provenance_json, license, completeness, state, installed_at, verified_at)
             VALUES(?1, ?2, X'01', 18, 'schema-eighteen', '1.0.0', 'producer', '1.0.0',
              'rust', 'cargo', NULL, X'7B7D', 'Apache-2.0', 'partial', 'verified', 1, 1)",
            params!["18".repeat(32), "7".repeat(64)],
        ).expect("schema 18 is admitted after migration 22");
        assert!(connection.execute(
            "UPDATE catalog_packs SET bifrost_compatibility = '*' WHERE schema_version = 17", []
        ).is_err(), "schema 17 retains native compatibility semantics");
        assert!(
            connection
                .execute(
                    "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 15, 'schema-fifteen-invalid', '1.0.0', 'producer', '1.0.0',
               'go', 'go', '*', X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                    params!["8".repeat(64), "e".repeat(64)],
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO catalog_packs(
               manifest_digest, semantic_digest, manifest_bytes, schema_version,
               pack_id, pack_version, producer_name, producer_version, language,
               ecosystem, bifrost_compatibility, provenance_json, license,
               completeness, state, installed_at, verified_at
             ) VALUES(?1, ?2, X'01', 16, 'schema-sixteen-invalid', '1.0.0', 'producer', '1.0.0',
               'python', 'pypi', '*', X'7B7D', 'Apache-2.0', 'complete', 'verified', 1, 1)",
                    params!["3".repeat(64), "8".repeat(64)],
                )
                .is_err()
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    #[hardwon("#3815: catalog schema rejection modified a read-only database")]
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
                CURRENT_CATALOG_VERSION + 1,
                CatalogError::CatalogTooNew {
                    found: CURRENT_CATALOG_VERSION + 1,
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
                    CatalogError::CatalogTooNew { found, supported },
                    CatalogError::CatalogTooNew {
                        found: expected_found,
                        supported: expected_supported,
                    },
                ) => {
                    assert_eq!((found, supported), (expected_found, expected_supported));
                }
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
        let root = TempDir::new().unwrap();
        let path = root.path().join(CATALOG_DB_FILE_NAME);
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        let mut connection = Connection::open(&path).unwrap();
        create_schema_10(&mut connection);
        migrate_native_compatibility(&mut connection).unwrap();
        drop(connection);
        let error = open(&root_path, CatalogOpenMode::ReadOnly).unwrap_err();
        assert!(matches!(
            error,
            CatalogError::ReadOnlySchema { found, required }
                if found == NATIVE_COMPATIBILITY_CATALOG_VERSION
                    && required == CURRENT_CATALOG_VERSION
        ));
    }

    #[test]
    #[hardwon("003c2dc95f7d: transient BUSY and PROTOCOL locks were not retried")]
    fn initialization_retry_admits_busy_and_locking_protocol_failures() {
        let mut attempts = 0;
        let value = retry_initialization_with(
            Duration::from_secs(1),
            |_| {},
            || {
                attempts += 1;
                match attempts {
                    1 => Err(brokk_bifrost_core::test_support::sqlite_error(
                        rusqlite::ffi::SQLITE_BUSY,
                    )),
                    2 => Err(brokk_bifrost_core::test_support::sqlite_error(
                        rusqlite::ffi::SQLITE_PROTOCOL,
                    )),
                    _ => Ok(42),
                }
            },
        )
        .unwrap();

        assert_eq!(value, 42);
        assert_eq!(attempts, 3);
    }

    #[test]
    #[hardwon("003c2dc95f7d: SQLITE_LOCKED must stay terminal")]
    fn initialization_retry_does_not_admit_other_sqlite_errors() {
        let mut attempts = 0;
        let error = retry_initialization_with(
            Duration::from_secs(1),
            |_| {},
            || {
                attempts += 1;
                Err::<(), _>(brokk_bifrost_core::test_support::sqlite_error(
                    rusqlite::ffi::SQLITE_LOCKED,
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error.sqlite_error_code(), Some(ErrorCode::DatabaseLocked));
        assert_eq!(attempts, 1);
    }

    #[test]
    #[hardwon("003c2dc95f7d: the final transient error must be returned at the deadline")]
    fn initialization_retry_returns_transient_error_at_deadline() {
        let mut attempts = 0;
        let error = retry_initialization_with(
            Duration::ZERO,
            |_| panic!("an expired retry must not sleep"),
            || {
                attempts += 1;
                Err::<(), _>(brokk_bifrost_core::test_support::sqlite_error(
                    rusqlite::ffi::SQLITE_PROTOCOL,
                ))
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
