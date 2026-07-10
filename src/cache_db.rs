//! Shared SQLite schema and connection setup for Bifrost's rebuildable cache.
//!
//! Issue #584 creates only the semantic namespace. The analyzer namespace is
//! reserved at version zero; no analyzer tables or query backend exist here.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};

use crate::path_normalization::NormalizePath;

pub(crate) type Result<T> = std::result::Result<T, String>;

pub(crate) const CACHE_DB_FILE_NAME: &str = "bifrost_cache.db";
pub(crate) const LEGACY_SEMANTIC_DB_FILE_NAME: &str = "semantic_cache.db";
pub(crate) const LATEST_SCHEMA_VERSION: i64 = 1;
pub(crate) const LATEST_SEMANTIC_SCHEMA_VERSION: i64 = 1;
pub(crate) const ANALYZER_SCHEMA_VERSION_NONE: i64 = 0;
pub(crate) const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);

pub(crate) fn open_unified_connection(db_path: &Path) -> Result<Connection> {
    ensure_safe_cache_path(db_path)?;
    let db_path = prepare_cache_db_path(db_path)?;
    ensure_safe_cache_path(&db_path)?;
    let directory_guard = CacheDirectoryGuard::open(
        db_path
            .parent()
            .ok_or_else(|| "cache database has no parent directory".to_string())?,
    )?;
    let mut conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    let initialized_before_open = unified_cache_initialized(&conn);
    let initialized = (|| {
        directory_guard.verify()?;
        configure_connection(&mut conn)?;
        migrate(&mut conn)?;
        directory_guard.verify()
    })();
    if let Err(err) = initialized {
        drop(conn);
        return Err(err);
    }
    if !initialized_before_open {
        // The legacy cache remains usable until the unified cache has opened and
        // migrated successfully. Cleanup is best-effort because both caches are
        // rebuildable and failure to delete an old warm cache must not fail open.
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
    let Some(parent) = db_path.parent() else {
        return Ok(db_path.to_path_buf().normalize());
    };
    std::fs::create_dir_all(parent).map_err(|err| format!("cache DB I/O error: {err}"))?;
    reject_symlink(parent, "cache directory")?;
    let Some(file_name) = db_path.file_name() else {
        return Ok(db_path.to_path_buf().normalize());
    };
    let canonical_parent = parent
        .canonicalize()
        .map_err(|err| format!("cache DB I/O error: {err}"))?
        .normalize();
    let expected_parent = parent
        .parent()
        .ok_or_else(|| "cache directory has no parent".to_string())?
        .canonicalize()
        .map_err(|err| format!("cache DB I/O error: {err}"))?
        .normalize()
        .join(
            parent
                .file_name()
                .ok_or_else(|| "cache directory has no final component".to_string())?,
        );
    if canonical_parent != expected_parent {
        return Err(format!(
            "refusing cache directory that resolves outside its requested path: {}",
            parent.display()
        ));
    }
    Ok(canonical_parent.join(file_name))
}

#[cfg(unix)]
struct CacheDirectoryGuard {
    path: PathBuf,
    directory: std::fs::File,
}

#[cfg(unix)]
impl CacheDirectoryGuard {
    fn open(path: &Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|err| format!("opening cache directory without symlink traversal: {err}"))?;
        let guard = Self {
            path: path.to_path_buf(),
            directory,
        };
        guard.verify()?;
        Ok(guard)
    }

    fn verify(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        reject_symlink(&self.path, "cache directory")?;
        let held = self
            .directory
            .metadata()
            .map_err(|err| format!("cache DB I/O error: {err}"))?;
        let current =
            std::fs::metadata(&self.path).map_err(|err| format!("cache DB I/O error: {err}"))?;
        if held.dev() != current.dev() || held.ino() != current.ino() {
            return Err(format!(
                "cache directory changed while opening {}",
                self.path.display()
            ));
        }
        Ok(())
    }
}

#[cfg(not(unix))]
struct CacheDirectoryGuard {
    path: PathBuf,
}

#[cfg(not(unix))]
impl CacheDirectoryGuard {
    fn open(path: &Path) -> Result<Self> {
        let guard = Self {
            path: path.to_path_buf(),
        };
        guard.verify()?;
        Ok(guard)
    }

    fn verify(&self) -> Result<()> {
        reject_symlink(&self.path, "cache directory")?;
        Ok(())
    }
}

pub(crate) fn configure_connection(conn: &mut Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_millis(5000))
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "ignore_check_constraints", "OFF")
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "recursive_triggers", "ON")
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "cache_size", -65536)
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "mmap_size", 268435456i64)
        .map_err(sqlite_error)?;
    conn.pragma_update(None, "wal_autocheckpoint", 2000)
        .map_err(sqlite_error)?;
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

pub(crate) fn migrate(conn: &mut Connection) -> Result<()> {
    assert_sqlite_version(conn)?;
    let state_exists = table_exists(conn, "cache_state")?;
    if !state_exists && !table_exists(conn, "meta")? {
        if user_table_names(conn)?.is_empty() {
            let tx = conn.transaction().map_err(sqlite_error)?;
            create_schema(&tx)?;
            initialize_cache_state(&tx)?;
            tx.commit().map_err(sqlite_error)?;
        } else {
            recreate_schema(conn)?;
        }
        return Ok(());
    }

    if !state_exists {
        recreate_schema(conn)?;
        return Ok(());
    }

    let versions: Option<(i64, i64, i64)> = conn
        .query_row(
            "SELECT schema_version, semantic_schema_version, analyzer_schema_version
             FROM cache_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((schema_version, semantic_version, analyzer_version)) = versions else {
        return Err("cache_state is missing its required id = 1 row".to_string());
    };
    if analyzer_version != ANALYZER_SCHEMA_VERSION_NONE {
        return Err(format!(
            "cache analyzer schema version {analyzer_version} is newer than this build supports"
        ));
    }
    if schema_version != LATEST_SCHEMA_VERSION || semantic_version != LATEST_SEMANTIC_SCHEMA_VERSION
    {
        recreate_schema(conn)?;
    }
    Ok(())
}

pub(crate) fn now_unix_seconds() -> i64 {
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
    let legacy_path = parent.join(LEGACY_SEMANTIC_DB_FILE_NAME);
    if !legacy_path.exists() {
        return;
    }
    let Ok(mut legacy) = Connection::open_with_flags(
        &legacy_path,
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
    // Windows does not allow unlinking a SQLite database while this connection
    // still owns file handles. The successful exclusive claim proves no live
    // legacy writer was present; close it before best-effort cleanup.
    drop(exclusive);
    drop(legacy);
    for suffix in ["", "-wal", "-shm"] {
        let path = parent.join(format!("{LEGACY_SEMANTIC_DB_FILE_NAME}{suffix}"));
        let _ = std::fs::remove_file(path);
    }
}

fn recreate_schema(conn: &mut Connection) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", "OFF")
        .map_err(sqlite_error)?;
    let result = (|| {
        let table_names = user_table_names(conn)?;
        let tx = conn.transaction().map_err(sqlite_error)?;
        for table_name in table_names {
            let quoted = format!("\"{}\"", table_name.replace('"', "\"\""));
            tx.execute_batch(&format!("DROP TABLE {quoted};"))
                .map_err(sqlite_error)?;
        }
        create_schema(&tx)?;
        initialize_cache_state(&tx)?;
        tx.commit().map_err(sqlite_error)
    })();
    let restore = conn
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(sqlite_error);
    result.and(restore)
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
    .map_err(sqlite_error)
}

fn user_table_names(conn: &Connection) -> Result<Vec<String>> {
    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .map_err(sqlite_error)?;
    let names = statement
        .query_map([], |row| row.get(0))
        .map_err(sqlite_error)?
        .collect::<std::result::Result<Vec<String>, _>>()
        .map_err(sqlite_error)?;
    Ok(names)
}

fn create_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE cache_state(
          id                       INTEGER PRIMARY KEY CHECK(id = 1),
          schema_version           INTEGER NOT NULL,
          semantic_schema_version  INTEGER NOT NULL,
          analyzer_schema_version  INTEGER NOT NULL CHECK(analyzer_schema_version >= 0),
          last_gc_at               INTEGER NOT NULL DEFAULT 0,
          blobs_at_last_gc         INTEGER NOT NULL DEFAULT 0,
          gc_claim_until           INTEGER NOT NULL DEFAULT 0,
          embed_fingerprint        TEXT,
          chunker_version          TEXT,
          bm25_tokenizer_version   TEXT
        ) STRICT;
        "#,
    )
    .map_err(sqlite_error)?;
    create_semantic_schema(tx)
}

fn create_semantic_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE semantic_blobs(
          blob_oid        TEXT PRIMARY KEY CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
          language        TEXT,
          materialized_at TEXT NOT NULL DEFAULT (datetime('now'))
        ) STRICT;

        CREATE TABLE semantic_blob_summaries(
          blob_summary_id INTEGER PRIMARY KEY,
          hash            BLOB NOT NULL UNIQUE CHECK(length(hash) = 32)
        ) STRICT;

        CREATE TABLE semantic_blob_chunks(
          blob_oid          TEXT NOT NULL REFERENCES semantic_blobs(blob_oid) ON DELETE CASCADE,
          chunk_ord         INTEGER NOT NULL,
          kind              TEXT NOT NULL,
          symbol            TEXT,
          start_line        INTEGER,
          end_line          INTEGER,
          fts_tokens        TEXT NOT NULL,
          hash              BLOB NOT NULL CHECK(length(hash) = 32),
          parent_summary_id INTEGER REFERENCES semantic_blob_summaries(blob_summary_id),
          composed_hash     BLOB NOT NULL CHECK(length(composed_hash) = 32),
          PRIMARY KEY(blob_oid, chunk_ord)
        ) WITHOUT ROWID, STRICT;
        CREATE INDEX semantic_blob_chunks_by_hash
          ON semantic_blob_chunks(hash);
        CREATE INDEX semantic_blob_chunks_by_parent
          ON semantic_blob_chunks(parent_summary_id);
        CREATE INDEX semantic_blob_chunks_by_composed
          ON semantic_blob_chunks(composed_hash);

        CREATE TABLE semantic_component_vectors(
          hash   BLOB PRIMARY KEY CHECK(length(hash) = 32),
          dim    INTEGER NOT NULL CHECK(dim > 0),
          vector BLOB NOT NULL
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE semantic_vectors(
          composed_hash BLOB PRIMARY KEY CHECK(length(composed_hash) = 32),
          dim           INTEGER NOT NULL CHECK(dim > 0),
          vector        BLOB NOT NULL
        ) WITHOUT ROWID, STRICT;
        "#,
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn initialize_cache_state(tx: &Transaction<'_>) -> Result<()> {
    tx.execute(
        "INSERT INTO cache_state(
           id, schema_version, semantic_schema_version, analyzer_schema_version,
           last_gc_at, blobs_at_last_gc, gc_claim_until
         ) VALUES(1, ?1, ?2, ?3, 0, 0, 0)",
        [
            LATEST_SCHEMA_VERSION,
            LATEST_SEMANTIC_SCHEMA_VERSION,
            ANALYZER_SCHEMA_VERSION_NONE,
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn assert_sqlite_version(conn: &Connection) -> Result<()> {
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let parsed = parse_sqlite_version(&version)
        .ok_or_else(|| format!("unable to parse SQLite version {version}"))?;
    if parsed < SQLITE_MIN_VERSION {
        return Err(format!(
            "SQLite {version} is too old; cache requires {}.{}.{} or newer",
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

fn sqlite_error(err: rusqlite::Error) -> String {
    format!("cache DB SQLite error: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
             )",
            [table],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    }

    fn create_legacy_db(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("CREATE TABLE legacy_cache(value TEXT) STRICT;")
            .unwrap();
    }

    #[test]
    fn creates_only_semantic_namespace_and_reserves_analyzer_zero() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();

        assert!(table_exists(&conn, "semantic_blobs"));
        assert!(table_exists(&conn, "semantic_blob_chunks"));
        assert!(!table_exists(&conn, "blobs"));
        assert!(!table_exists(&conn, "analysis_epochs"));
        assert!(!table_exists(&conn, "code_units"));
        let analyzer_version: i64 = conn
            .query_row(
                "SELECT analyzer_schema_version FROM cache_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(analyzer_version, ANALYZER_SCHEMA_VERSION_NONE);
    }

    #[test]
    fn schema_mismatch_rebuilds_semantic_namespace() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO semantic_blobs(blob_oid) VALUES(?1)",
            ["1111111111111111111111111111111111111111"],
        )
        .unwrap();
        conn.execute(
            "UPDATE cache_state SET schema_version = 999 WHERE id = 1",
            [],
        )
        .unwrap();
        conn.execute_batch("CREATE TABLE analyzer_stale(id INTEGER PRIMARY KEY) STRICT;")
            .unwrap();

        migrate(&mut conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM semantic_blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        assert!(!table_exists(&conn, "analyzer_stale"));
    }

    #[test]
    fn future_analyzer_schema_is_refused_without_mutation() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn.execute_batch("CREATE TABLE analyzer_future(id INTEGER PRIMARY KEY) STRICT;")
            .unwrap();
        conn.execute(
            "UPDATE cache_state SET analyzer_schema_version = 1 WHERE id = 1",
            [],
        )
        .unwrap();

        let err = migrate(&mut conn).unwrap_err();
        assert!(err.contains("newer than this build supports"), "{err}");
        assert!(table_exists(&conn, "semantic_blobs"));
        assert!(table_exists(&conn, "analyzer_future"));
        let version: i64 = conn
            .query_row(
                "SELECT analyzer_schema_version FROM cache_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn missing_cache_state_row_is_reported_without_rebuild() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        conn.execute("DELETE FROM cache_state", []).unwrap();

        let err = migrate(&mut conn).unwrap_err();
        assert!(err.contains("missing its required id = 1 row"), "{err}");
        assert!(table_exists(&conn, "semantic_blobs"));
    }

    #[test]
    fn first_unified_open_deletes_only_legacy_semantic_files() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        create_legacy_db(&cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME));
        let unrelated = cache_dir.join("analyzer_cache.db");
        std::fs::write(&unrelated, b"unrelated").unwrap();

        let db_path = cache_dir.join(CACHE_DB_FILE_NAME);
        let _conn = open_unified_connection(&db_path).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            assert!(
                !cache_dir
                    .join(format!("{LEGACY_SEMANTIC_DB_FILE_NAME}{suffix}"))
                    .exists()
            );
        }
        assert!(unrelated.exists());
    }

    #[test]
    fn existing_unified_db_leaves_legacy_file_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let db_path = cache_dir.join(CACHE_DB_FILE_NAME);
        let _conn = open_unified_connection(&db_path).unwrap();
        let legacy = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
        create_legacy_db(&legacy);

        let _second = open_unified_connection(&db_path).unwrap();
        assert!(legacy.exists());
    }

    #[test]
    fn arbitrary_or_legacy_db_path_never_triggers_legacy_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
        create_legacy_db(&legacy);

        let custom = cache_dir.join("custom.db");
        let _custom = open_unified_connection(&custom).unwrap();
        assert!(legacy.exists());

        let _legacy = open_unified_connection(&legacy).unwrap();
        assert!(legacy.exists());
    }

    #[test]
    fn live_legacy_writer_prevents_first_open_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let legacy_path = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
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

        let unified = cache_dir.join(CACHE_DB_FILE_NAME);
        let _conn = open_unified_connection(&unified).unwrap();
        assert!(legacy_path.exists());
        writer.rollback().unwrap();
    }

    #[test]
    fn incomplete_unified_creation_cleans_legacy_after_later_success() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let db_path = cache_dir.join(CACHE_DB_FILE_NAME);
        let partial = Connection::open(&db_path).unwrap();
        partial
            .execute_batch("CREATE TABLE interrupted(value TEXT) STRICT;")
            .unwrap();
        drop(partial);
        let legacy = cache_dir.join(LEGACY_SEMANTIC_DB_FILE_NAME);
        create_legacy_db(&legacy);

        let conn = open_unified_connection(&db_path).unwrap();
        assert!(table_exists(&conn, "semantic_blobs"));
        assert!(!table_exists(&conn, "interrupted"));
        assert!(!legacy.exists());
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
        assert!(err.contains("cache directory symlink"), "unexpected: {err}");
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
        assert!(err.contains("cache database symlink"), "unexpected: {err}");
        assert!(!outside.exists());
    }

    #[cfg(unix)]
    #[test]
    fn directory_guard_detects_cache_directory_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        let guard = CacheDirectoryGuard::open(&cache_dir).unwrap();
        std::fs::rename(&cache_dir, temp.path().join("original")).unwrap();
        std::fs::create_dir(&cache_dir).unwrap();

        let err = guard.verify().unwrap_err();
        assert!(err.contains("changed while opening"), "unexpected: {err}");
    }
}
