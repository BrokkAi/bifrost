//! Shared SQLite schema and connection setup for bifrost's rebuildable cache DB.

use std::path::{Path, PathBuf};
use std::time::Duration;

use once_cell::sync::Lazy;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use rusqlite_migration::{M, Migrations};

pub type Result<T> = std::result::Result<T, String>;

pub const CACHE_DB_FILE_NAME: &str = "bifrost_cache.db";
pub const LEGACY_SEMANTIC_DB_FILE_NAME: &str = "semantic_cache.db";
pub const LEGACY_ANALYZER_DB_FILE_NAME: &str = "analyzer_cache.db";

const BASELINE_MIGRATION_VERSION: i64 = 1;
const BASELINE_CACHE_STATE_VERSIONS: (i64, i64, i64) = (1, 1, 10);
const BASELINE_TABLE_NAMES: &[&str] = &[
    "cache_state",
    "semantic_blobs",
    "semantic_blob_summaries",
    "semantic_blob_chunks",
    "semantic_component_vectors",
    "semantic_vectors",
    "analysis_epochs",
    "blobs",
    "code_units",
    "unit_ranges",
    "unit_signatures",
    "unit_signature_metadata",
    "unit_supertypes",
    "unit_children",
    "ruby_method_dispatch_modes",
    "scala_traits",
    "import_statements",
    "import_details",
    "blob_meta",
    "type_identifiers",
];
const CURRENT_BASELINE_SQL: &str = include_str!("../migrations/cache/0001-current-baseline.sql");
static CACHE_MIGRATIONS: Lazy<Migrations<'static>> =
    Lazy::new(|| Migrations::new(vec![M::up(CURRENT_BASELINE_SQL)]));
pub const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);

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
    let initialized_before_open = unified_cache_initialized(&conn);
    configure_connection(&mut conn)?;
    migrate(&mut conn)?;
    if !initialized_before_open {
        delete_legacy_cache_files(&db_path);
    }
    Ok(conn)
}

fn unified_cache_initialized(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM sqlite_master
           WHERE type = 'table' AND name = 'cache_state'
         ) AND EXISTS(
           SELECT 1 FROM cache_state WHERE id = 1
         )",
        [],
        |row| row.get(0),
    )
    .unwrap_or(false)
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
    conn.busy_timeout(Duration::from_millis(5000))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "ignore_check_constraints", "OFF")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "recursive_triggers", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
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
    Ok(())
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
    prepare_baseline_migration(conn)?;
    CACHE_MIGRATIONS
        .to_latest(conn)
        .map_err(|err| format!("cache DB migration error: {err}"))
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

fn recreate_schema(conn: &mut Connection) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", "OFF")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let result = (|| {
        let table_names = user_table_names(conn)?;
        let tx = conn
            .transaction()
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        for table_name in table_names {
            let quoted = format!("\"{}\"", table_name.replace('"', "\"\""));
            tx.execute_batch(&format!("DROP TABLE {quoted};"))
                .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        }
        tx.execute_batch("PRAGMA user_version = 0;")
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        tx.commit()
            .map_err(|err| format!("cache DB SQLite error: {err}"))
    })();
    let restore = conn
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("cache DB SQLite error: {err}"));
    result.and(restore)
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

fn user_table_names(conn: &Connection) -> Result<Vec<String>> {
    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    statement
        .query_map([], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?
        .collect::<std::result::Result<Vec<String>, _>>()
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}
fn prepare_baseline_migration(conn: &mut Connection) -> Result<()> {
    let user_version = cache_migration_version(conn)?;
    if user_version < 0 {
        return Err(format!(
            "cache DB migration user_version must not be negative: {user_version}"
        ));
    }
    if user_version > BASELINE_MIGRATION_VERSION {
        return Ok(());
    }

    let table_names = user_table_names(conn)?;
    if user_version == 0 && table_names.is_empty() {
        return Ok(());
    }

    if baseline_schema_is_valid(conn)? {
        if user_version == 0 {
            adopt_current_baseline(conn)?;
        }
        return Ok(());
    }

    recreate_schema(conn)
}

fn cache_migration_version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn baseline_schema_is_valid(conn: &Connection) -> Result<bool> {
    if !quick_check_is_ok(conn)? {
        return Ok(false);
    }
    let table_names = user_table_names(conn)?;
    if table_names.len() != BASELINE_TABLE_NAMES.len()
        || BASELINE_TABLE_NAMES
            .iter()
            .any(|table| !table_names.iter().any(|name| name == table))
    {
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

fn quick_check_is_ok(conn: &Connection) -> Result<bool> {
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(result == "ok")
}

fn adopt_current_baseline(conn: &mut Connection) -> Result<()> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    if cache_migration_version(&tx)? != 0 {
        return Ok(());
    }
    if !baseline_schema_is_valid(&tx)? {
        return Err("cache DB baseline changed while being adopted".to_string());
    }
    tx.execute_batch("PRAGMA user_version = 1;")
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    tx.commit()
        .map_err(|err| format!("cache DB SQLite error: {err}"))
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

    fn future_migrations(sql: &'static str) -> Migrations<'static> {
        Migrations::new(vec![M::up(CURRENT_BASELINE_SQL), M::up(sql)])
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

        assert_eq!(cache_migration_version(&conn).unwrap(), 1);
        assert!(baseline_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn current_pre_migration_cache_is_adopted_without_dropping_rows() {
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
        assert_eq!(cache_migration_version(&conn).unwrap(), 1);
        assert_eq!(semantic_count, 1);
        assert_eq!(analyzer_count, 1);
    }

    #[test]
    fn incomplete_pre_migration_cache_is_rebuilt() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(cache_migration_version(&conn).unwrap(), 1);
        assert!(!table_exists(&conn, "legacy_cache").unwrap());
        assert!(baseline_schema_is_valid(&conn).unwrap());
    }

    #[test]
    fn pre_migration_cache_with_unrecognized_table_is_rebuilt() {
        let mut conn = create_current_baseline_without_migration();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(cache_migration_version(&conn).unwrap(), 1);
        assert!(!table_exists(&conn, "legacy_cache").unwrap());
        assert!(baseline_schema_is_valid(&conn).unwrap());
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

        assert_eq!(cache_migration_version(&conn).unwrap(), 1);
        assert!(baseline_schema_is_valid(&conn).unwrap());
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
            future_migrations("CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;");

        migrations.to_latest(&mut conn).unwrap();

        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(cache_migration_version(&conn).unwrap(), 2);
        assert_eq!(analyzer_count, 1);
        assert!(table_exists(&conn, "migration_probe").unwrap());
    }

    #[test]
    fn failing_migration_rolls_back_schema_and_version() {
        let mut conn = open_in_memory_cache();
        let migrations = future_migrations(
            "CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;
             this is not valid SQL;",
        );

        assert!(migrations.to_latest(&mut conn).is_err());

        assert_eq!(cache_migration_version(&conn).unwrap(), 1);
        assert!(!table_exists(&conn, "migration_probe").unwrap());
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
        let migrations =
            future_migrations("CREATE TABLE migration_probe(value TEXT NOT NULL) STRICT;");

        assert!(migrations.to_latest(&mut conn).is_err());
        assert_eq!(cache_migration_version(&conn).unwrap(), 1);
        assert!(!table_exists(&conn, "migration_probe").unwrap());

        writer.rollback().unwrap();
        migrations.to_latest(&mut conn).unwrap();

        assert_eq!(cache_migration_version(&conn).unwrap(), 2);
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
        conn.execute_batch("PRAGMA user_version = 2;").unwrap();

        let err = migrate(&mut conn).unwrap_err();

        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert!(
            err.contains("DatabaseTooFarAhead"),
            "unexpected error: {err}"
        );
        assert_eq!(cache_migration_version(&conn).unwrap(), 2);
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

        assert!(unified_cache_initialized(&connection));
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

        assert_eq!(cache_migration_version(&connection).unwrap(), 1);
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
