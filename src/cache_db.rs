//! Shared SQLite schema and connection setup for Bifrost's rebuildable cache.
//!
//! Issue #584 creates only the semantic namespace. The analyzer namespace is
//! reserved at version zero; no analyzer tables or query backend exist here.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction};

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
    delete_legacy_cache_files_on_first_open(&db_path)?;
    let mut conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    configure_connection(&mut conn)?;
    migrate(&mut conn)?;
    Ok(conn)
}

fn prepare_cache_db_path(db_path: &Path) -> Result<PathBuf> {
    let Some(parent) = db_path.parent() else {
        return Ok(db_path.to_path_buf().normalize());
    };
    std::fs::create_dir_all(parent).map_err(|err| format!("cache DB I/O error: {err}"))?;
    let Some(file_name) = db_path.file_name() else {
        return Ok(db_path.to_path_buf().normalize());
    };
    let parent = parent
        .canonicalize()
        .map_err(|err| format!("cache DB I/O error: {err}"))?
        .normalize();
    Ok(parent.join(file_name))
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
    let current = schema_version(conn)?;
    if current == 0 {
        let tx = conn.transaction().map_err(sqlite_error)?;
        create_schema(&tx)?;
        initialize_cache_state(&tx)?;
        tx.commit().map_err(sqlite_error)?;
        return Ok(());
    }
    if current != LATEST_SCHEMA_VERSION {
        recreate_schema(conn)?;
        return Ok(());
    }

    let (semantic_version, analyzer_version): (i64, i64) = conn
        .query_row(
            "SELECT semantic_schema_version, analyzer_schema_version
             FROM cache_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if semantic_version != LATEST_SEMANTIC_SCHEMA_VERSION
        || analyzer_version != ANALYZER_SCHEMA_VERSION_NONE
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

fn delete_legacy_cache_files_on_first_open(db_path: &Path) -> Result<()> {
    if db_path.exists() {
        return Ok(());
    }
    let Some(parent) = db_path.parent() else {
        return Ok(());
    };
    for suffix in ["", "-wal", "-shm"] {
        let path = parent.join(format!("{LEGACY_SEMANTIC_DB_FILE_NAME}{suffix}"));
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("removing legacy cache {}: {err}", path.display())),
        }
    }
    Ok(())
}

fn recreate_schema(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction().map_err(sqlite_error)?;
    drop_semantic_schema(&tx)?;
    tx.execute_batch(
        "DROP TABLE IF EXISTS cache_state;
         DROP TABLE IF EXISTS meta;",
    )
    .map_err(sqlite_error)?;
    create_schema(&tx)?;
    initialize_cache_state(&tx)?;
    tx.commit().map_err(sqlite_error)?;
    Ok(())
}

fn drop_semantic_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        "DROP TABLE IF EXISTS semantic_blob_chunks;
         DROP TABLE IF EXISTS semantic_blob_summaries;
         DROP TABLE IF EXISTS semantic_blobs;
         DROP TABLE IF EXISTS semantic_vectors;
         DROP TABLE IF EXISTS semantic_component_vectors;
         DROP TABLE IF EXISTS blob_chunks;
         DROP TABLE IF EXISTS blob_summaries;
         DROP TABLE IF EXISTS blobs;
         DROP TABLE IF EXISTS vectors;
         DROP TABLE IF EXISTS component_vectors;",
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn create_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE cache_state(
          id                       INTEGER PRIMARY KEY CHECK(id = 1),
          schema_version           INTEGER NOT NULL,
          semantic_schema_version  INTEGER NOT NULL,
          analyzer_schema_version  INTEGER NOT NULL CHECK(analyzer_schema_version = 0),
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

fn schema_version(conn: &Connection) -> Result<i64> {
    let state_exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'cache_state'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if state_exists.is_some() {
        return conn
            .query_row(
                "SELECT schema_version FROM cache_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.unwrap_or(0))
            .map_err(sqlite_error);
    }

    let meta_exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if meta_exists.is_none() {
        return Ok(0);
    }
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'schema_version'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map(|value| value.and_then(|value| value.parse().ok()).unwrap_or(0))
    .map_err(sqlite_error)
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

        migrate(&mut conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM semantic_blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn first_unified_open_deletes_only_legacy_semantic_files() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join(".brokk");
        std::fs::create_dir(&cache_dir).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            std::fs::write(
                cache_dir.join(format!("{LEGACY_SEMANTIC_DB_FILE_NAME}{suffix}")),
                b"legacy",
            )
            .unwrap();
        }
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
        std::fs::write(&legacy, b"legacy").unwrap();

        let _second = open_unified_connection(&db_path).unwrap();
        assert!(legacy.exists());
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
}
