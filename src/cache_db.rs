//! Shared SQLite schema and connection setup for bifrost's rebuildable cache DB.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use rusqlite::ffi::ErrorCode;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
#[cfg(test)]
use rusqlite_migration::{M, Migrations};

pub type Result<T> = std::result::Result<T, String>;

pub const CACHE_DB_FILE_NAME: &str = "bifrost_cache.db";
pub const LEGACY_SEMANTIC_DB_FILE_NAME: &str = "semantic_cache.db";
pub const LEGACY_ANALYZER_DB_FILE_NAME: &str = "analyzer_cache.db";

const BASELINE_MIGRATION_VERSION: i64 = 1;
const CURRENT_MIGRATION_VERSION: i64 = 10;
const BASELINE_CACHE_STATE_VERSIONS: (i64, i64, i64) = (1, 1, 10);
const CURRENT_BASELINE_SQL: &str = include_str!("../migrations/cache/0001-current-baseline.sql");
const PATH_SYMBOL_UNITS_SQL: &str = include_str!("../migrations/cache/0002-path-symbol-units.sql");
const FORWARD_FACTS_SQL: &str = include_str!("../migrations/cache/0003-forward-facts.sql");
const ANALYZER_GENERATIONS_SQL: &str =
    include_str!("../migrations/cache/0004-analyzer-generations.sql");
const ANALYZER_BLOB_CASCADE_COSTS_SQL: &str =
    include_str!("../migrations/cache/0005-analyzer-blob-cascade-costs.sql");
const ANALYZER_BLOB_PAYLOAD_COSTS_SQL: &str =
    include_str!("../migrations/cache/0006-analyzer-blob-payload-costs.sql");
const STRUCTURAL_FACTS_SNAPSHOTS_SQL: &str =
    include_str!("../migrations/cache/0007-structural-facts-snapshots.sql");
const CPP_TEMPLATE_METADATA_SQL: &str =
    include_str!("../migrations/cache/0008-cpp-template-metadata.sql");
const SCALA_EXPORTS_SQL: &str = include_str!("../migrations/cache/0009-scala-exports.sql");
const IDENTIFIER_LOOKUP_MEMBERSHIP_SQL: &str =
    include_str!("../migrations/cache/0010-identifier-lookup-membership.sql");
const CACHE_MIGRATION_SQL: [&str; CURRENT_MIGRATION_VERSION as usize] = [
    CURRENT_BASELINE_SQL,
    PATH_SYMBOL_UNITS_SQL,
    FORWARD_FACTS_SQL,
    ANALYZER_GENERATIONS_SQL,
    ANALYZER_BLOB_CASCADE_COSTS_SQL,
    ANALYZER_BLOB_PAYLOAD_COSTS_SQL,
    STRUCTURAL_FACTS_SNAPSHOTS_SQL,
    CPP_TEMPLATE_METADATA_SQL,
    SCALA_EXPORTS_SQL,
    IDENTIFIER_LOOKUP_MEMBERSHIP_SQL,
];
#[cfg(test)]
static CACHE_MIGRATIONS: Lazy<Migrations<'static>> =
    Lazy::new(|| Migrations::new(CACHE_MIGRATION_SQL.into_iter().map(M::up).collect()));
static BASELINE_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open baseline schema connection");
    conn.execute_batch(CURRENT_BASELINE_SQL)
        .expect("create baseline schema");
    schema_object_definitions(&conn).expect("read baseline schema definitions")
});
#[cfg(test)]
static CURRENT_SCHEMA_OBJECTS: Lazy<Vec<(String, String, String)>> = Lazy::new(|| {
    let conn = Connection::open_in_memory().expect("open current schema connection");
    conn.execute_batch(CURRENT_BASELINE_SQL)
        .expect("create baseline schema");
    conn.execute_batch(PATH_SYMBOL_UNITS_SQL)
        .expect("apply path symbol migration");
    conn.execute_batch(FORWARD_FACTS_SQL)
        .expect("apply forward facts migration");
    conn.execute_batch(ANALYZER_GENERATIONS_SQL)
        .expect("apply analyzer generations migration");
    conn.execute_batch(ANALYZER_BLOB_CASCADE_COSTS_SQL)
        .expect("apply analyzer blob cascade costs migration");
    conn.execute_batch(ANALYZER_BLOB_PAYLOAD_COSTS_SQL)
        .expect("apply analyzer blob payload costs migration");
    conn.execute_batch(STRUCTURAL_FACTS_SNAPSHOTS_SQL)
        .expect("apply structural facts snapshots migration");
    conn.execute_batch(CPP_TEMPLATE_METADATA_SQL)
        .expect("apply C++ template metadata migration");
    conn.execute_batch(SCALA_EXPORTS_SQL)
        .expect("apply Scala exports migration");
    conn.execute_batch(IDENTIFIER_LOOKUP_MEMBERSHIP_SQL)
        .expect("apply identifier lookup membership migration");
    schema_object_definitions(&conn).expect("read current schema definitions")
});
pub const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-connection prepared-statement cache capacity. rusqlite defaults to 16,
/// which is far too small for our query surface: `format!`-spliced predicates
/// and (now fixed-arity) `IN` lists produce dozens of distinct SQL shapes, and
/// a 16-slot cache thrashes, re-preparing/finalizing hot statements inside the
/// critical section. 64 covers the observed shape count with headroom.
const PREPARED_STATEMENT_CACHE_CAPACITY: usize = 64;
const INITIALIZATION_RETRY_DEADLINE: Duration = BUSY_TIMEOUT;
const INITIALIZATION_RETRY_BACKOFF: Duration = Duration::from_millis(5);
const INITIALIZATION_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(100);

pub fn open_unified_connection(db_path: &Path) -> Result<Connection> {
    ensure_safe_cache_path(db_path)?;
    let db_path = prepare_cache_db_path(db_path)?;
    ensure_safe_cache_path(&db_path)?;
    let mut conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    configure_connection_after_busy_timeout(&mut conn)?;
    let initialized_before_open = unified_cache_initialized(&conn)?;
    migrate(&mut conn)?;
    if !initialized_before_open {
        delete_legacy_cache_files(&db_path);
    }
    Ok(conn)
}

/// Open a read-only connection to an already-initialized cache DB.
///
/// The writer connection (`open_unified_connection`) is responsible for
/// creating the file, running migrations, and establishing WAL mode — all of
/// which are persistent database properties. A reader therefore opens with
/// `SQLITE_OPEN_READ_ONLY` (making "a reader cannot write" a hard, SQLite-level
/// invariant) and applies only the read-relevant pragmas. Under WAL a read-only
/// connection still reads the writer's committed snapshots as long as the
/// process can access the `-wal`/`-shm` sidecars, which it can: the same process
/// created the DB and holds the writer open for the store's lifetime.
pub fn open_readonly_connection(db_path: &Path) -> Result<Connection> {
    ensure_safe_cache_path(db_path)?;
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    install_busy_timeout(&conn)?;
    configure_readonly_connection(&conn)?;
    Ok(conn)
}

/// Apply the pragmas that matter for a read-only WAL connection. Deliberately
/// omits every write/schema-mutating pragma the writer path runs
/// (`journal_mode`, `auto_vacuum`, `foreign_keys`, `wal_autocheckpoint`,
/// `synchronous`, …): those are either persistent file properties already
/// established by the writer or illegal to set on a read-only handle.
fn configure_readonly_connection(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "cache_size", -65536)
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "mmap_size", 268435456i64)
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.pragma_update(None, "query_only", "ON")
        .map_err(|err| format!("cache DB read-only SQLite error: {err}"))?;
    conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
    Ok(())
}

fn unified_cache_initialized(conn: &Connection) -> Result<bool> {
    let has_cache_state: bool = conn
        .query_row(
            "SELECT EXISTS(
           SELECT 1 FROM sqlite_master
           WHERE type = 'table' AND name = 'cache_state'
         )",
            [],
            |row| row.get(0),
        )
        .map_err(|err| format!("cache DB initialization-state query SQLite error: {err}"))?;
    if !has_cache_state {
        return Ok(false);
    }
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM cache_state WHERE id = 1)",
        [],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache DB initialization-state query SQLite error: {err}"))
}

fn prepare_cache_db_path(db_path: &Path) -> Result<PathBuf> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("cache DB I/O error: {err}"))?;
        if let Some(file_name) = db_path.file_name() {
            let parent = parent
                .canonicalize()
                .map_err(|err| format!("cache DB I/O error: {err}"))?;
            return Ok(parent.join(file_name));
        }
    }
    Ok(db_path.to_path_buf())
}

pub fn configure_connection(conn: &mut Connection) -> Result<()> {
    install_busy_timeout(conn)?;
    configure_connection_after_busy_timeout(conn)
}

fn install_busy_timeout(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(|err| format!("cache DB busy-timeout configuration SQLite error: {err}"))
}

fn configure_connection_after_busy_timeout(conn: &mut Connection) -> Result<()> {
    if conn.path().is_some_and(|path| !path.is_empty()) {
        retry_initialization_phase("auto-vacuum initialization", || {
            ensure_incremental_auto_vacuum(conn)
        })?;
        retry_initialization_phase("journal-mode initialization", || {
            ensure_wal_journal_mode(conn)
        })?;
    }
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "ignore_check_constraints", "OFF")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "recursive_triggers", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "cache_size", -65536)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "mmap_size", 268435456i64)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "wal_autocheckpoint", 2000)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
    Ok(())
}

enum InitializationPhaseError {
    Sqlite(rusqlite::Error),
    Verification(String),
}

impl From<rusqlite::Error> for InitializationPhaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

fn ensure_wal_journal_mode(conn: &Connection) -> std::result::Result<(), InitializationPhaseError> {
    let current: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if current.eq_ignore_ascii_case("wal") {
        return Ok(());
    }
    let updated: String =
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if updated.eq_ignore_ascii_case("wal") {
        Ok(())
    } else {
        Err(InitializationPhaseError::Verification(format!(
            "requested WAL but SQLite reported {updated}"
        )))
    }
}

fn ensure_incremental_auto_vacuum(
    conn: &Connection,
) -> std::result::Result<(), InitializationPhaseError> {
    let current: i64 = conn.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if current == 2 {
        return Ok(());
    }
    let schema_is_empty: bool = conn.query_row(
        "SELECT NOT EXISTS(
           SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'
         )",
        [],
        |row| row.get(0),
    )?;
    // SQLite cannot change a populated mode-0 database without VACUUM. Cache
    // compatibility wins over an implicit full rewrite; existing databases keep
    // their current mode, while fresh databases are configured before migration.
    if current == 0 && !schema_is_empty {
        return Ok(());
    }
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    let updated: i64 = conn.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if updated == 2 {
        Ok(())
    } else {
        Err(InitializationPhaseError::Verification(format!(
            "requested INCREMENTAL (2) but SQLite reported {updated}"
        )))
    }
}

fn retry_initialization_phase<T>(
    phase: &str,
    operation: impl FnMut() -> std::result::Result<T, InitializationPhaseError>,
) -> Result<T> {
    retry_initialization_phase_with(
        phase,
        INITIALIZATION_RETRY_DEADLINE,
        std::thread::sleep,
        operation,
    )
}

fn retry_initialization_phase_with<T>(
    phase: &str,
    deadline: Duration,
    mut sleep: impl FnMut(Duration),
    mut operation: impl FnMut() -> std::result::Result<T, InitializationPhaseError>,
) -> Result<T> {
    let started = Instant::now();
    let mut backoff = INITIALIZATION_RETRY_BACKOFF;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(InitializationPhaseError::Sqlite(error))
                if error.sqlite_error_code() == Some(ErrorCode::DatabaseBusy) =>
            {
                let elapsed = started.elapsed();
                if elapsed >= deadline {
                    return Err(format!(
                        "cache DB {phase} timed out after {elapsed:?}: {error}"
                    ));
                }
                sleep(backoff.min(deadline.saturating_sub(elapsed)));
                let elapsed = started.elapsed();
                if elapsed >= deadline {
                    return Err(format!(
                        "cache DB {phase} timed out after {elapsed:?}: {error}"
                    ));
                }
                backoff = backoff
                    .saturating_mul(2)
                    .min(INITIALIZATION_RETRY_MAX_BACKOFF);
            }
            Err(InitializationPhaseError::Sqlite(error)) => {
                return Err(format!("cache DB {phase} SQLite error: {error}"));
            }
            Err(InitializationPhaseError::Verification(error)) => {
                return Err(format!("cache DB {phase} verification failed: {error}"));
            }
        }
    }
}

fn ensure_safe_cache_path(db_path: &Path) -> Result<()> {
    let Some(parent) = db_path.parent() else {
        return Ok(());
    };
    reject_symlink(parent, "cache directory")?;
    reject_symlink(db_path, "cache database")?;
    reject_symlink(&db_path.with_extension("db-wal"), "cache WAL")?;
    reject_symlink(&db_path.with_extension("db-shm"), "cache SHM")?;
    Ok(())
}

fn reject_symlink(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "refusing to use {label} symlink {}",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("cache DB I/O error: {err}")),
    }
}

pub fn migrate(conn: &mut Connection) -> Result<()> {
    assert_sqlite_version(conn)?;
    migrate_with_sql(conn, &CACHE_MIGRATION_SQL)
}

fn migrate_with_sql(conn: &mut Connection, migrations: &[&str]) -> Result<()> {
    let user_version = cache_migration_version(conn)?;
    if current_schema_fast_path(migrations, user_version) {
        return Ok(());
    }
    // Ordinary migrations keep FK enforcement enabled because their DELETEs rely on
    // cascades. Rebuilding an invalid schema needs it disabled, but SQLite cannot
    // change foreign_keys inside a transaction. The first locked pass makes no
    // changes when it detects that case; after toggling, the repair pass reacquires
    // the write lock and re-inspects before rebuilding and migrating atomically.
    if matches!(
        migrate_with_sql_locked(conn, migrations, false)?,
        LockedMigrationOutcome::Complete
    ) {
        return Ok(());
    }

    conn.pragma_update(None, "foreign_keys", "OFF")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let result = match migrate_with_sql_locked(conn, migrations, true) {
        Ok(LockedMigrationOutcome::Complete) => Ok(()),
        Ok(LockedMigrationOutcome::RebuildRequired) => {
            Err("cache DB schema rebuild was not applied".to_string())
        }
        Err(err) => Err(err),
    };
    let restore = conn
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"));
    result.and(restore)
}

enum LockedMigrationOutcome {
    Complete,
    RebuildRequired,
}

enum BaselinePreparation {
    Ready(i64),
    RebuildRequired,
}

fn migrate_with_sql_locked(
    conn: &mut Connection,
    migrations: &[&str],
    rebuild_invalid_schema: bool,
) -> Result<LockedMigrationOutcome> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let user_version = cache_migration_version(&tx)?;
    if user_version < 0 {
        return Err(format!(
            "cache DB migration user_version must not be negative: {user_version}"
        ));
    }
    if user_version as usize > migrations.len() {
        return Err(format!(
            "cache DB migration error: DatabaseTooFarAhead: user_version {user_version} exceeds {}",
            migrations.len()
        ));
    }
    if current_schema_fast_path(migrations, user_version) {
        tx.commit()
            .map_err(|err| format!("cache DB migration fast-path commit error: {err}"))?;
        return Ok(LockedMigrationOutcome::Complete);
    }

    let user_version = match prepare_baseline_migration(&tx, user_version, rebuild_invalid_schema)?
    {
        BaselinePreparation::Ready(user_version) => user_version,
        BaselinePreparation::RebuildRequired => {
            return Ok(LockedMigrationOutcome::RebuildRequired);
        }
    };
    let mut migration_applied = false;
    for (index, sql) in migrations.iter().enumerate().skip(user_version as usize) {
        let version = index + 1;
        tx.execute_batch(sql)
            .map_err(|err| format!("cache DB migration error applying version {version}: {err}"))?;
        tx.pragma_update(None, "user_version", version)
            .map_err(|err| format!("cache DB migration error setting version {version}: {err}"))?;
        migration_applied = true;
    }
    if migration_applied {
        validate_foreign_keys(&tx)?;
    }
    tx.commit()
        .map_err(|err| format!("cache DB migration error: {err}"))?;
    Ok(LockedMigrationOutcome::Complete)
}

pub fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0)
}

fn delete_legacy_cache_files(db_path: &Path) {
    if db_path.file_name() != Some(std::ffi::OsStr::new(CACHE_DB_FILE_NAME)) {
        return;
    }
    let Some(parent) = db_path.parent() else {
        return;
    };
    for name in [LEGACY_SEMANTIC_DB_FILE_NAME, LEGACY_ANALYZER_DB_FILE_NAME] {
        delete_legacy_cache_if_idle(&parent.join(name));
    }
}

fn delete_legacy_cache_if_idle(legacy_path: &Path) {
    if !legacy_path.exists() {
        return;
    }
    let Ok(mut legacy) = Connection::open_with_flags(
        legacy_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ) else {
        return;
    };
    if legacy.busy_timeout(Duration::ZERO).is_err()
        || legacy
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .is_err()
    {
        return;
    }
    let checkpoint_busy = legacy
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(1);
    if checkpoint_busy != 0 {
        return;
    }
    let Ok(exclusive) = legacy.transaction_with_behavior(TransactionBehavior::Exclusive) else {
        return;
    };
    // Close first: Windows cannot unlink a database while the claiming handle is open.
    drop(exclusive);
    drop(legacy);
    let Some(file_name) = legacy_path.file_name() else {
        return;
    };
    for suffix in ["", "-wal", "-shm"] {
        let mut name = file_name.to_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(legacy_path.with_file_name(name));
    }
}

fn recreate_schema(tx: &Transaction<'_>) -> Result<()> {
    for (object_type, name) in user_schema_objects(tx)? {
        let quoted = format!("\"{}\"", name.replace('"', "\"\""));
        tx.execute_batch(&format!("DROP {object_type} {quoted};"))
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    }
    tx.pragma_update(None, "user_version", 0)
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

#[cfg(test)]
fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn user_schema_objects(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
               AND type IN ('view', 'trigger', 'table')
             ORDER BY CASE type
                 WHEN 'view' THEN 0
                 WHEN 'trigger' THEN 1
                 WHEN 'table' THEN 2
                 ELSE 3
             END, name",
        )
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?
        .collect::<std::result::Result<Vec<(String, String)>, _>>()
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn schema_object_definitions(conn: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
             ORDER BY type, name",
        )
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    statement
        .query_map([], |row| {
            let sql: String = row.get(2)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                sql.chars()
                    .filter(|character| !character.is_whitespace())
                    .collect(),
            ))
        })
        .map_err(|err| format!("cache DB SQLite error: {err}"))?
        .collect::<std::result::Result<Vec<(String, String, String)>, _>>()
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn prepare_baseline_migration(
    tx: &Transaction<'_>,
    user_version: i64,
    rebuild_invalid_schema: bool,
) -> Result<BaselinePreparation> {
    if user_version > BASELINE_MIGRATION_VERSION {
        return Ok(BaselinePreparation::Ready(user_version));
    }

    if user_version == 0 && user_schema_objects(tx)?.is_empty() {
        return Ok(BaselinePreparation::Ready(0));
    }

    if baseline_schema_is_valid(tx)? {
        if user_version == 0 {
            adopt_current_baseline(tx)?;
            return Ok(BaselinePreparation::Ready(BASELINE_MIGRATION_VERSION));
        }
        return Ok(BaselinePreparation::Ready(user_version));
    }

    if !rebuild_invalid_schema {
        return Ok(BaselinePreparation::RebuildRequired);
    }
    recreate_schema(tx)?;
    Ok(BaselinePreparation::Ready(0))
}

fn cache_migration_version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn baseline_schema_is_valid(conn: &Connection) -> Result<bool> {
    if !quick_check_is_ok(conn)? {
        return Ok(false);
    }
    if schema_object_definitions(conn)? != *BASELINE_SCHEMA_OBJECTS {
        return Ok(false);
    }
    let versions = conn.query_row(
        "SELECT schema_version, semantic_schema_version, analyzer_schema_version
         FROM cache_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    Ok(matches!(versions, Ok(versions) if versions == BASELINE_CACHE_STATE_VERSIONS))
}

#[cfg(test)]
fn current_schema_is_valid(conn: &Connection) -> Result<bool> {
    if !quick_check_is_ok(conn)? {
        return Ok(false);
    }
    if schema_object_definitions(conn)? != *CURRENT_SCHEMA_OBJECTS {
        return Ok(false);
    }
    let versions = conn.query_row(
        "SELECT schema_version, semantic_schema_version, analyzer_schema_version
         FROM cache_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    Ok(matches!(versions, Ok(versions) if versions == BASELINE_CACHE_STATE_VERSIONS))
}

fn current_schema_fast_path(migrations: &[&str], user_version: i64) -> bool {
    migrations == CACHE_MIGRATION_SQL.as_slice() && user_version == CURRENT_MIGRATION_VERSION
}

fn quick_check_is_ok(conn: &Connection) -> Result<bool> {
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(result == "ok")
}

fn adopt_current_baseline(tx: &Transaction<'_>) -> Result<()> {
    if cache_migration_version(tx)? != 0 {
        return Ok(());
    }
    if !baseline_schema_is_valid(tx)? {
        return Err("cache DB baseline changed while being adopted".to_string());
    }
    tx.pragma_update(None, "user_version", BASELINE_MIGRATION_VERSION)
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn validate_foreign_keys(conn: &Connection) -> Result<()> {
    let violations: i64 = conn
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    if violations == 0 {
        Ok(())
    } else {
        Err(format!(
            "cache DB migration foreign key validation failed with {violations} violation(s)"
        ))
    }
}

fn assert_sqlite_version(conn: &Connection) -> Result<()> {
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let parsed = parse_sqlite_version(&version)
        .ok_or_else(|| format!("unable to parse sqlite_version() output: {version}"))?;
    if parsed < SQLITE_MIN_VERSION {
        return Err(format!(
            "cache DB requires sqlite >= {}.{}.{} but found {version}",
            SQLITE_MIN_VERSION.0, SQLITE_MIN_VERSION.1, SQLITE_MIN_VERSION.2
        ));
    }
    Ok(())
}

fn parse_sqlite_version(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use rusqlite_migration::{M, Migrations};

    use super::*;

    fn open_in_memory_cache() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn
    }

    fn create_current_baseline_without_migration() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        conn.execute_batch(CURRENT_BASELINE_SQL).unwrap();
        conn
    }

    fn future_migration_sql(sql: &'static str) -> Vec<&'static str> {
        CACHE_MIGRATION_SQL
            .into_iter()
            .chain(std::iter::once(sql))
            .collect()
    }

    fn create_legacy_cache(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
    }

    #[test]
    fn baseline_migration_validates() {
        CACHE_MIGRATIONS.validate().unwrap();
    }

    #[test]
    fn fresh_cache_applies_baseline_migration() {
        let conn = open_in_memory_cache();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn concurrent_fresh_cache_openers_serialize_schema_migration() {
        const OPENERS: usize = 16;

        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(CACHE_DB_FILE_NAME);
        let barrier = Arc::new(Barrier::new(OPENERS));
        let results = thread::scope(|scope| {
            let handles = (0..OPENERS)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let db_path = db_path.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        let conn = open_unified_connection(&db_path)?;
                        if cache_migration_version(&conn)? != CURRENT_MIGRATION_VERSION {
                            return Err("concurrent opener observed an old schema version".into());
                        }
                        if !current_schema_is_valid(&conn)? {
                            return Err("concurrent opener observed an invalid schema".into());
                        }
                        let foreign_keys: i64 = conn
                            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
                        if foreign_keys != 1 {
                            return Err("concurrent opener left foreign keys disabled".into());
                        }
                        let journal_mode: String = conn
                            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
                        if !journal_mode.eq_ignore_ascii_case("wal") {
                            return Err(format!(
                                "concurrent opener observed journal_mode={journal_mode}"
                            ));
                        }
                        let auto_vacuum: i64 = conn
                            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
                            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
                        if auto_vacuum != 2 {
                            return Err(format!(
                                "concurrent opener observed auto_vacuum={auto_vacuum}"
                            ));
                        }
                        Ok(())
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("cache opener thread panicked"))
                .collect::<Vec<_>>()
        });

        assert!(
            results.iter().all(Result::is_ok),
            "concurrent cache openers failed: {results:#?}"
        );
        let conn = open_unified_connection(&db_path).unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
        assert!(quick_check_is_ok(&conn).unwrap());
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );
        assert_eq!(
            conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn populated_mode_zero_cache_keeps_compatible_auto_vacuum_policy() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(CACHE_DB_FILE_NAME);
        let mut conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE existing(value TEXT) STRICT;")
            .unwrap();
        assert_eq!(
            conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );

        configure_connection(&mut conn).unwrap();

        assert_eq!(
            conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0,
            "populated mode-0 databases require an explicit VACUUM and must not be reported as converted"
        );
        assert_eq!(
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );
    }

    fn sqlite_initialization_error(code: i32) -> InitializationPhaseError {
        InitializationPhaseError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            None,
        ))
    }

    #[test]
    fn initialization_retry_retries_busy_but_not_locked() {
        let mut busy_attempts = 0;
        let value = retry_initialization_phase_with(
            "test busy phase",
            Duration::from_secs(1),
            |_| {},
            || {
                busy_attempts += 1;
                if busy_attempts < 3 {
                    Err(sqlite_initialization_error(rusqlite::ffi::SQLITE_BUSY))
                } else {
                    Ok(42)
                }
            },
        )
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(busy_attempts, 3);

        let mut locked_attempts = 0;
        let error = retry_initialization_phase_with(
            "test locked phase",
            Duration::from_secs(1),
            |_| {},
            || {
                locked_attempts += 1;
                Err::<(), _>(sqlite_initialization_error(rusqlite::ffi::SQLITE_LOCKED))
            },
        )
        .unwrap_err();
        assert_eq!(locked_attempts, 1);
        assert!(error.contains("test locked phase SQLite error"), "{error}");
        assert!(!error.contains("timed out"), "{error}");
    }

    #[test]
    fn initialization_retry_reports_busy_deadline_without_sleeping() {
        let mut attempts = 0;
        let error = retry_initialization_phase_with(
            "test timeout phase",
            Duration::ZERO,
            |_| panic!("zero-deadline retry must not sleep"),
            || {
                attempts += 1;
                Err::<(), _>(sqlite_initialization_error(rusqlite::ffi::SQLITE_BUSY))
            },
        )
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert!(error.contains("test timeout phase timed out"), "{error}");
    }

    #[test]
    fn current_pre_migration_cache_preserves_semantic_rows_and_invalidates_analyzer_rows() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute(
            "INSERT INTO semantic_blobs(blob_oid, language) VALUES(?1, 'rust')",
            ["1111111111111111111111111111111111111111"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            ["2222222222222222222222222222222222222222"],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let semantic_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM semantic_blobs", [], |row| row.get(0))
            .unwrap();
        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(semantic_count, 1);
        assert_eq!(analyzer_count, 0);
    }

    #[test]
    fn analyzer_migrations_preserve_populated_v3_rows_with_lazy_payload_costs() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        Migrations::new(vec![
            M::up(CURRENT_BASELINE_SQL),
            M::up(PATH_SYMBOL_UNITS_SQL),
            M::up(FORWARD_FACTS_SQL),
        ])
        .to_latest(&mut conn)
        .unwrap();
        let semantic_oid = "1111111111111111111111111111111111111111";
        let analyzer_oid = "2222222222222222222222222222222222222222";
        conn.execute(
            "INSERT INTO semantic_blobs(blob_oid, language) VALUES(?1, 'rust')",
            [semantic_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO type_identifiers(blob_oid, lang, type_identifier)
             VALUES(?1, 'rust', 'PersistedType')",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_oid, lang, contains_tests, content_package, stored_unit_count,
               range_count, signature_count, signature_metadata_count, supertype_count,
               child_count, import_statement_count, import_count, type_identifier_count,
               ruby_dispatch_count, scala_trait_count, is_complete
             ) VALUES(?1, 'rust', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1)",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO path_symbol_units(
               lang, rel_path, blob_oid, kind, package_name, short_name,
               exact_fqn, normalized_fqn
             ) VALUES('rust', 'src/lib.rs', ?1, 0, 'src', 'lib', 'src.lib', 'src.lib')",
            [analyzer_oid],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            conn.query_row("SELECT generation FROM blobs", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blob_payload_costs", [], |row| row
                .get::<_, i64>(0),)
                .unwrap(),
            0,
            "the migration must preserve populated analyzer rows for lazy fallback"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('blobs')
                 WHERE name IN ('cascade_logical_rows', 'cascade_payload_bytes')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2,
            "the published v5 columns must remain present after additive v6 migration"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blob_meta", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM type_identifiers", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT generation FROM path_symbol_units", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM semantic_blobs", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn populated_v5_cache_migrates_additively_to_v7() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        Migrations::new(vec![
            M::up(CURRENT_BASELINE_SQL),
            M::up(PATH_SYMBOL_UNITS_SQL),
            M::up(FORWARD_FACTS_SQL),
            M::up(ANALYZER_GENERATIONS_SQL),
            M::up(ANALYZER_BLOB_CASCADE_COSTS_SQL),
        ])
        .to_latest(&mut conn)
        .unwrap();
        let analyzer_oid = "2222222222222222222222222222222222222222";
        conn.execute(
            "INSERT INTO blobs(
               blob_oid, lang, generation, cascade_logical_rows, cascade_payload_bytes
             ) VALUES(?1, 'rust', 7, 3, 11)",
            [analyzer_oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_oid, lang, contains_tests, content_package, stored_unit_count,
               range_count, signature_count, signature_metadata_count, supertype_count,
               child_count, import_statement_count, import_count, type_identifier_count,
               ruby_dispatch_count, scala_trait_count, is_complete
             ) VALUES(?1, 'rust', 0, 'unicode_é', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)",
            [analyzer_oid],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert_eq!(
            conn.query_row(
                "SELECT generation, cascade_logical_rows, cascade_payload_bytes FROM blobs",
                [],
                |row| Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?
                )),
            )
            .unwrap(),
            (7, 3, 11),
            "later additive migrations must not reinterpret already-applied v5 state"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blob_payload_costs", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0,
            "existing parsed blobs intentionally retain the v6 legacy-fallback state"
        );
        assert_eq!(
            conn.query_row("SELECT content_package FROM blob_meta", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "unicode_é"
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn incomplete_pre_migration_cache_is_rebuilt() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "legacy_cache").unwrap());
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn pre_migration_cache_with_unrecognized_table_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "legacy_cache").unwrap());
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn pre_migration_cache_with_incomplete_table_shape_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch(
            "DROP TABLE blob_meta;
             CREATE TABLE blob_meta(
               blob_oid TEXT NOT NULL,
               lang TEXT NOT NULL,
               PRIMARY KEY(blob_oid, lang)
             ) WITHOUT ROWID, STRICT;",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let has_content_package: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM pragma_table_info('blob_meta')
                   WHERE name = 'content_package'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(has_content_package);
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn pre_migration_cache_with_unrecognized_view_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE VIEW legacy_view AS SELECT 1 AS value;")
            .unwrap();

        migrate(&mut conn).unwrap();

        let legacy_view_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master WHERE type = 'view' AND name = 'legacy_view'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!legacy_view_exists);
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn incomplete_current_cache_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch(
            "DROP TABLE semantic_vectors;
             PRAGMA user_version = 1;",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(current_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn future_migration_preserves_baseline_rows() {
        let mut conn = open_in_memory_cache();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            ["2222222222222222222222222222222222222222"],
        )
        .unwrap();
        let migrations =
            future_migration_sql("CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;");

        migrate_with_sql(&mut conn, &migrations).unwrap();

        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION + 1
        );
        assert_eq!(analyzer_count, 1);
        assert!(table_exists(&conn, "migration_probe").unwrap());
    }

    #[test]
    fn failing_migration_rolls_back_schema_and_version() {
        let mut conn = open_in_memory_cache();
        let migrations = future_migration_sql(
            "CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;
             this is not valid SQL;",
        );

        assert!(migrate_with_sql(&mut conn, &migrations).is_err());

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "migration_probe").unwrap());
        assert_eq!(
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn foreign_key_validation_rolls_back_schema_and_version() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
        let migrations = future_migration_sql(
            "INSERT INTO blob_payload_costs(blob_oid, lang, payload_bytes)
             VALUES('0000000000000000000000000000000000000000', 'rust', 0);",
        );

        let err = migrate_with_sql(&mut conn, &migrations).unwrap_err();

        assert!(
            err.contains("foreign key validation failed"),
            "unexpected error: {err}"
        );
        assert_eq!(cache_migration_version(&conn).unwrap(), 0);
        assert!(table_exists(&conn, "legacy_cache").unwrap());
        assert!(!table_exists(&conn, "blob_payload_costs").unwrap());
        assert_eq!(
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn locked_migration_retries_after_writer_releases_lock() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(CACHE_DB_FILE_NAME);
        let mut conn = Connection::open(&db_path).unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn.busy_timeout(Duration::ZERO).unwrap();

        let mut blocker = Connection::open(&db_path).unwrap();
        blocker.busy_timeout(Duration::ZERO).unwrap();
        let writer = blocker
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        migrate(&mut conn).expect("a valid current schema must not wait for the write lock");
        let migrations =
            future_migration_sql("CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;");

        assert!(migrate_with_sql(&mut conn, &migrations).is_err());
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(!table_exists(&conn, "migration_probe").unwrap());
        assert_eq!(
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );

        writer.rollback().unwrap();
        migrate_with_sql(&mut conn, &migrations).unwrap();

        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION + 1
        );
        assert!(table_exists(&conn, "migration_probe").unwrap());
    }

    #[test]
    fn newer_migration_version_is_refused_without_mutating_cache() {
        let mut conn = open_in_memory_cache();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            ["2222222222222222222222222222222222222222"],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", CURRENT_MIGRATION_VERSION + 1)
            .unwrap();

        let err = migrate(&mut conn).unwrap_err();

        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert!(
            err.contains("DatabaseTooFarAhead"),
            "unexpected error: {err}"
        );
        assert_eq!(
            cache_migration_version(&conn).unwrap(),
            CURRENT_MIGRATION_VERSION + 1
        );
        assert_eq!(analyzer_count, 1);
    }

    #[test]
    fn first_unified_open_removes_only_idle_legacy_caches_after_migration() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        for name in [LEGACY_SEMANTIC_DB_FILE_NAME, LEGACY_ANALYZER_DB_FILE_NAME] {
            create_legacy_cache(&cache_dir.join(name));
        }

        let unified = cache_dir.join(CACHE_DB_FILE_NAME);
        let connection = open_unified_connection(&unified).unwrap();

        assert!(unified_cache_initialized(&connection).unwrap());
        for name in [LEGACY_SEMANTIC_DB_FILE_NAME, LEGACY_ANALYZER_DB_FILE_NAME] {
            assert!(!cache_dir.join(name).exists());
        }
    }

    #[test]
    fn baseline_adoption_does_not_remove_legacy_caches() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
        create_legacy_cache(&legacy);

        let unified = cache_dir.join(CACHE_DB_FILE_NAME);
        let mut pre_migration = Connection::open(&unified).unwrap();
        configure_connection(&mut pre_migration).unwrap();
        pre_migration.execute_batch(CURRENT_BASELINE_SQL).unwrap();
        drop(pre_migration);

        let connection = open_unified_connection(&unified).unwrap();

        assert_eq!(
            cache_migration_version(&connection).unwrap(),
            CURRENT_MIGRATION_VERSION
        );
        assert!(legacy.exists());
    }

    #[test]
    fn custom_database_open_does_not_remove_legacy_caches() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
        create_legacy_cache(&legacy);

        let _custom = open_unified_connection(&cache_dir.join("custom.db")).unwrap();

        assert!(legacy.exists());
    }

    #[test]
    fn active_legacy_writer_survives_first_unified_open() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy_path = cache_dir.join(LEGACY_ANALYZER_DB_FILE_NAME);
        let mut legacy = Connection::open(&legacy_path).unwrap();
        legacy.pragma_update(None, "journal_mode", "WAL").unwrap();
        legacy
            .execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
        let writer = legacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        writer
            .execute("INSERT INTO legacy_cache(value) VALUES('active')", [])
            .unwrap();

        let _unified = open_unified_connection(&cache_dir.join(CACHE_DB_FILE_NAME)).unwrap();

        assert!(legacy_path.exists());
        writer.rollback().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let cache_dir = temp.path().join(".brokk");
        symlink(&outside, &cache_dir).unwrap();

        let err = open_unified_connection(&cache_dir.join(CACHE_DB_FILE_NAME)).unwrap_err();
        assert!(
            err.contains("cache directory symlink"),
            "unexpected error: {err}"
        );
        assert!(!outside.join(CACHE_DB_FILE_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_database() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let outside = temp.path().join("outside.db");
        symlink(&outside, cache_dir.join(CACHE_DB_FILE_NAME)).unwrap();

        let err = open_unified_connection(&cache_dir.join(CACHE_DB_FILE_NAME)).unwrap_err();
        assert!(
            err.contains("cache database symlink"),
            "unexpected error: {err}"
        );
        assert!(!outside.exists());
    }
}
