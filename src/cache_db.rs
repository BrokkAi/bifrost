//! Shared SQLite schema and connection setup for bifrost's rebuildable cache DB.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction};

pub type Result<T> = std::result::Result<T, String>;

pub const CACHE_DB_FILE_NAME: &str = "bifrost_cache.db";
pub const LEGACY_SEMANTIC_DB_FILE_NAME: &str = "semantic_cache.db";
pub const LEGACY_ANALYZER_DB_FILE_NAME: &str = "analyzer_cache.db";

pub const LATEST_SCHEMA_VERSION: i64 = 6;
const LATEST_SEMANTIC_SCHEMA_VERSION: i64 = 1;
const LATEST_ANALYZER_SCHEMA_VERSION: i64 = 7;
pub const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);

pub fn open_unified_connection(db_path: &Path) -> Result<Connection> {
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
    let current = schema_version(conn)?;
    if current == 0 {
        let tx = conn
            .transaction()
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        create_schema(&tx)?;
        initialize_cache_state(&tx)?;
        tx.commit()
            .map_err(|err| format!("cache DB SQLite error: {err}"))?;
        return Ok(());
    }
    if current != LATEST_SCHEMA_VERSION {
        recreate_schema(conn)?;
        return Ok(());
    }
    let (semantic_version, analyzer_version) = namespace_schema_versions(conn)?;
    if semantic_version != LATEST_SEMANTIC_SCHEMA_VERSION {
        recreate_semantic_schema(conn)?;
    }
    if analyzer_version != LATEST_ANALYZER_SCHEMA_VERSION {
        recreate_analyzer_schema(conn)?;
    }
    Ok(())
}

pub fn now_unix_seconds() -> i64 {
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
    for name in [LEGACY_SEMANTIC_DB_FILE_NAME, LEGACY_ANALYZER_DB_FILE_NAME] {
        for suffix in ["", "-wal", "-shm"] {
            let path = parent.join(format!("{name}{suffix}"));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(format!("removing legacy cache {}: {err}", path.display())),
            }
        }
    }
    Ok(())
}

fn recreate_schema(conn: &mut Connection) -> Result<()> {
    let tx = conn
        .transaction()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    drop_semantic_schema(&tx)?;
    drop_analyzer_schema(&tx)?;
    tx.execute_batch(
        "DROP TABLE IF EXISTS cache_state;
         DROP TABLE IF EXISTS meta;",
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    create_schema(&tx)?;
    initialize_cache_state(&tx)?;
    tx.commit()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(())
}

fn recreate_semantic_schema(conn: &mut Connection) -> Result<()> {
    let tx = conn
        .transaction()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    drop_semantic_schema(&tx)?;
    create_semantic_schema(&tx)?;
    tx.execute(
        "UPDATE cache_state
         SET semantic_schema_version = ?1,
             embed_fingerprint = NULL,
             chunker_version = NULL,
             bm25_tokenizer_version = NULL,
             last_gc_at = 0,
             blobs_at_last_gc = 0
         WHERE id = 1",
        [LATEST_SEMANTIC_SCHEMA_VERSION],
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    tx.commit()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(())
}

fn recreate_analyzer_schema(conn: &mut Connection) -> Result<()> {
    let tx = conn
        .transaction()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    drop_analyzer_schema(&tx)?;
    create_analyzer_schema(&tx)?;
    tx.execute(
        "UPDATE cache_state
         SET analyzer_schema_version = ?1,
             last_gc_at = 0,
             blobs_at_last_gc = 0
         WHERE id = 1",
        [LATEST_ANALYZER_SCHEMA_VERSION],
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    tx.commit()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
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
         DROP TABLE IF EXISTS vectors;
         DROP TABLE IF EXISTS component_vectors;",
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(())
}

fn drop_analyzer_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        "DROP TABLE IF EXISTS import_details;
         DROP TABLE IF EXISTS import_statements;
         DROP TABLE IF EXISTS imports;
         DROP TABLE IF EXISTS type_identifiers;
         DROP TABLE IF EXISTS blob_meta;
         DROP TABLE IF EXISTS scala_traits;
         DROP TABLE IF EXISTS ruby_method_dispatch_modes;
         DROP TABLE IF EXISTS unit_children;
         DROP TABLE IF EXISTS unit_supertypes;
         DROP TABLE IF EXISTS unit_signature_metadata;
         DROP TABLE IF EXISTS unit_signatures;
         DROP TABLE IF EXISTS unit_ranges;
         DROP TABLE IF EXISTS code_units;
         DROP TABLE IF EXISTS blobs;
         DROP TABLE IF EXISTS analysis_epochs;",
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(())
}

fn create_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE cache_state(
          id                       INTEGER PRIMARY KEY CHECK(id = 1),
          schema_version           INTEGER NOT NULL,
          semantic_schema_version  INTEGER NOT NULL,
          analyzer_schema_version  INTEGER NOT NULL,
          last_gc_at               INTEGER NOT NULL DEFAULT 0,
          blobs_at_last_gc         INTEGER NOT NULL DEFAULT 0,
          gc_claim_until           INTEGER NOT NULL DEFAULT 0,
          embed_fingerprint        TEXT,
          chunker_version          TEXT,
          bm25_tokenizer_version   TEXT
        ) STRICT;
        "#,
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    create_semantic_schema(tx)?;
    create_analyzer_schema(tx)?;
    Ok(())
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
          dim    INTEGER NOT NULL,
          vector BLOB NOT NULL
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE semantic_vectors(
          composed_hash BLOB PRIMARY KEY CHECK(length(composed_hash) = 32),
          dim           INTEGER NOT NULL,
          vector        BLOB NOT NULL
        ) WITHOUT ROWID, STRICT;
        "#,
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(())
}

fn create_analyzer_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE analysis_epochs(
          lang  TEXT PRIMARY KEY,
          epoch TEXT NOT NULL
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE blobs(
          blob_oid TEXT NOT NULL CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
          lang     TEXT NOT NULL,
          PRIMARY KEY(blob_oid, lang)
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE code_units(
          blob_oid                 TEXT    NOT NULL,
          lang                     TEXT    NOT NULL,
          unit_key                 INTEGER NOT NULL,
          kind                     INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 5),
          short_name               TEXT    NOT NULL,
          content_qualifier        TEXT    NOT NULL,
          signature                TEXT,
          synthetic                INTEGER NOT NULL CHECK(synthetic IN (0, 1)),
          is_type_alias            INTEGER NOT NULL CHECK(is_type_alias IN (0, 1)),
          top_level_ordinal        INTEGER CHECK(top_level_ordinal IS NULL OR top_level_ordinal >= 0),
          in_declarations          INTEGER NOT NULL CHECK(in_declarations IN (0, 1)),
          in_definition_lookup     INTEGER NOT NULL CHECK(in_definition_lookup IN (0, 1)),
          PRIMARY KEY(blob_oid, lang, unit_key),
          CHECK(kind <> 5),
          CHECK(NOT (kind = 3 AND lang IN ('javascript', 'python', 'typescript'))),
          FOREIGN KEY(blob_oid, lang)
            REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE INDEX idx_code_units_lang_short_name
          ON code_units(lang, short_name);

        CREATE TABLE unit_ranges(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          unit_key    INTEGER NOT NULL,
          ordinal     INTEGER NOT NULL,
          start_byte  INTEGER NOT NULL,
          end_byte    INTEGER NOT NULL,
          start_line  INTEGER NOT NULL,
          end_line    INTEGER NOT NULL,
          PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
          CHECK(start_byte >= 0 AND end_byte >= start_byte AND start_line >= 0 AND end_line >= start_line),
          FOREIGN KEY(blob_oid, lang, unit_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE INDEX idx_unit_ranges_lang_blob_ordinal
          ON unit_ranges(lang, blob_oid, ordinal);

        CREATE TABLE unit_signatures(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          unit_key    INTEGER NOT NULL,
          ordinal     INTEGER NOT NULL,
          text        TEXT    NOT NULL,
          PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
          FOREIGN KEY(blob_oid, lang, unit_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE unit_signature_metadata(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          unit_key    INTEGER NOT NULL,
          ordinal     INTEGER NOT NULL,
          metadata    BLOB    NOT NULL,
          PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
          FOREIGN KEY(blob_oid, lang, unit_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE unit_supertypes(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          unit_key    INTEGER NOT NULL,
          ordinal     INTEGER NOT NULL,
          raw         TEXT    NOT NULL,
          PRIMARY KEY(blob_oid, lang, unit_key, ordinal),
          FOREIGN KEY(blob_oid, lang, unit_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE unit_children(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          parent_key  INTEGER NOT NULL,
          child_key   INTEGER NOT NULL,
          ordinal     INTEGER NOT NULL,
          PRIMARY KEY(blob_oid, lang, parent_key, child_key, ordinal),
          CHECK(parent_key <> child_key),
          FOREIGN KEY(blob_oid, lang, parent_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE,
          FOREIGN KEY(blob_oid, lang, child_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE ruby_method_dispatch_modes(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          unit_key    INTEGER NOT NULL,
          mode        INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 2),
          PRIMARY KEY(blob_oid, lang, unit_key),
          FOREIGN KEY(blob_oid, lang, unit_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE scala_traits(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          unit_key    INTEGER NOT NULL,
          PRIMARY KEY(blob_oid, lang, unit_key),
          FOREIGN KEY(blob_oid, lang, unit_key)
            REFERENCES code_units(blob_oid, lang, unit_key) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE import_statements(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          ordinal     INTEGER NOT NULL,
          statement   TEXT    NOT NULL,
          PRIMARY KEY(blob_oid, lang, ordinal),
          FOREIGN KEY(blob_oid, lang)
            REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE import_details(
          blob_oid    TEXT    NOT NULL,
          lang        TEXT    NOT NULL,
          ordinal     INTEGER NOT NULL,
          info        BLOB    NOT NULL,
          PRIMARY KEY(blob_oid, lang, ordinal),
          FOREIGN KEY(blob_oid, lang)
            REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE blob_meta(
          blob_oid           TEXT    NOT NULL,
          lang               TEXT    NOT NULL,
          contains_tests     INTEGER NOT NULL CHECK(contains_tests IN (0, 1)),
          content_package    TEXT    NOT NULL,
          stored_unit_count  INTEGER NOT NULL CHECK(stored_unit_count >= 0),
          range_count         INTEGER NOT NULL CHECK(range_count >= 0),
          signature_count     INTEGER NOT NULL CHECK(signature_count >= 0),
          signature_metadata_count INTEGER NOT NULL CHECK(signature_metadata_count >= 0),
          supertype_count     INTEGER NOT NULL CHECK(supertype_count >= 0),
          child_count         INTEGER NOT NULL CHECK(child_count >= 0),
          import_statement_count INTEGER NOT NULL CHECK(import_statement_count >= 0),
          import_count        INTEGER NOT NULL CHECK(import_count >= 0),
          type_identifier_count INTEGER NOT NULL CHECK(type_identifier_count >= 0),
          ruby_dispatch_count INTEGER NOT NULL CHECK(ruby_dispatch_count >= 0),
          scala_trait_count   INTEGER NOT NULL CHECK(scala_trait_count >= 0),
          is_complete         INTEGER NOT NULL CHECK(is_complete IN (0, 1)),
          PRIMARY KEY(blob_oid, lang),
          FOREIGN KEY(blob_oid, lang)
            REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;

        CREATE TABLE type_identifiers(
          blob_oid         TEXT NOT NULL,
          lang             TEXT NOT NULL,
          type_identifier  TEXT NOT NULL,
          PRIMARY KEY(blob_oid, lang, type_identifier),
          FOREIGN KEY(blob_oid, lang)
            REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
        ) WITHOUT ROWID, STRICT;
        "#,
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
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
            LATEST_ANALYZER_SCHEMA_VERSION,
        ],
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    Ok(())
}

fn namespace_schema_versions(conn: &Connection) -> Result<(i64, i64)> {
    conn.query_row(
        "SELECT semantic_schema_version, analyzer_schema_version
         FROM cache_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(|err| format!("cache DB SQLite error: {err}"))
}

fn schema_version(conn: &Connection) -> Result<i64> {
    let state_exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'cache_state'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    if state_exists.is_some() {
        return conn
            .query_row(
                "SELECT schema_version FROM cache_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map(|version| version.unwrap_or(0))
            .map_err(|err| format!("cache DB SQLite error: {err}"));
    }
    let meta_exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    if meta_exists.is_none() {
        return Ok(0);
    }
    let legacy: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| format!("cache DB SQLite error: {err}"))?;
    legacy
        .as_deref()
        .unwrap_or("0")
        .parse::<i64>()
        .map_err(|err| format!("invalid cache DB schema version: {err}"))
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
    use super::*;

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

    #[test]
    fn analyzer_namespace_rebuild_preserves_semantic_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
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
        conn.execute(
            "UPDATE cache_state SET analyzer_schema_version = 0 WHERE id = 1",
            [],
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let semantic_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM semantic_blobs", [], |row| row.get(0))
            .unwrap();
        let analyzer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(semantic_count, 1);
        assert_eq!(analyzer_count, 0);
    }
}
