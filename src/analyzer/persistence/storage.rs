//! SQLite-backed analyzer storage.
//!
//! One DB per project, language column on every row. The storage exposes:
//!
//! - `open` — create file if missing, run sequential migrations, run
//!   `PRAGMA integrity_check`. A failure at any of these steps is reported
//!   as a `PersistenceError` so callers can fall back to a full rebuild.
//! - `read_baseline` — load every persisted row for a language as a
//!   `BTreeMap` keyed by relative path.
//! - `commit_reconcile` — apply one workspace's worth of writes/deletes in
//!   a single transaction and bump the language epoch.

use crate::analyzer::Language;
use crate::analyzer::persistence::migrations;
use rusqlite::{Connection, OpenFlags, params};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// File name used inside the cache directory.
pub const DB_FILE_NAME: &str = "analyzer.db";

/// Cache directory under the project root.
pub const DEFAULT_CACHE_DIR: &str = ".bifrost";

/// Returns `<project_root>/.bifrost/analyzer.db`.
pub fn default_db_path(project_root: impl AsRef<Path>) -> PathBuf {
    project_root
        .as_ref()
        .join(DEFAULT_CACHE_DIR)
        .join(DB_FILE_NAME)
}

#[derive(Debug)]
pub enum PersistenceError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    IntegrityCheck(String),
    Encode(String),
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "analyzer storage I/O error: {err}"),
            Self::Sqlite(err) => write!(f, "analyzer storage SQLite error: {err}"),
            Self::IntegrityCheck(detail) => {
                write!(f, "analyzer storage integrity check failed: {detail}")
            }
            Self::Encode(detail) => write!(f, "analyzer storage encode error: {detail}"),
        }
    }
}

impl Error for PersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Sqlite(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PersistenceError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<rusqlite::Error> for PersistenceError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

pub type Result<T> = std::result::Result<T, PersistenceError>;

/// One row from `analyzed_files`.
#[derive(Debug, Clone)]
pub struct BaselineRow {
    pub mtime_ns: i64,
    pub size: i64,
    pub epoch: String,
    pub payload: Vec<u8>,
}

/// Inputs to `commit_reconcile`: a write replaces (or inserts) one row.
#[derive(Debug)]
pub struct WriteRow {
    pub rel_path: String,
    pub mtime_ns: i64,
    pub size: i64,
    pub payload: Vec<u8>,
}

/// SQLite-backed analyzer cache. Thread-safe via an internal mutex; multiple
/// language analyzers in the same process share one instance.
pub struct AnalyzerStorage {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl fmt::Debug for AnalyzerStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalyzerStorage")
            .field("path", &self.path)
            .finish()
    }
}

impl AnalyzerStorage {
    /// Open or create the analyzer DB at `path`. Runs sequential migrations
    /// and `PRAGMA integrity_check` before returning. The parent directory
    /// is created if it does not exist.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;

        run_integrity_check(&conn)?;
        migrations::migrate(&mut conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load every persisted row for `language` keyed by relative path
    /// (forward slashes, matching `ProjectFile::rel_path` formatting).
    pub fn read_baseline(&self, language: Language) -> Result<BTreeMap<String, BaselineRow>> {
        let lang = language_key(language);
        let conn = self.conn.lock().expect("analyzer storage mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT rel_path, mtime_ns, size, epoch, payload \
             FROM analyzed_files \
             WHERE language = ?1",
        )?;
        let rows = stmt.query_map([lang], |row| {
            Ok((
                row.get::<_, String>(0)?,
                BaselineRow {
                    mtime_ns: row.get(1)?,
                    size: row.get(2)?,
                    epoch: row.get(3)?,
                    payload: row.get(4)?,
                },
            ))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (path, baseline) = row?;
            out.insert(path, baseline);
        }
        Ok(out)
    }

    /// Read the persisted epoch for a language, if any.
    pub fn read_epoch(&self, language: Language) -> Result<Option<String>> {
        let lang = language_key(language);
        let conn = self.conn.lock().expect("analyzer storage mutex poisoned");
        let value: rusqlite::Result<String> = conn.query_row(
            "SELECT epoch FROM analyzer_epoch WHERE language = ?1",
            [lang],
            |row| row.get(0),
        );
        match value {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Atomically apply one reconcile result: upsert every `WriteRow`,
    /// delete every path in `deletes`, and bump the analyzer epoch.
    pub fn commit_reconcile(
        &self,
        language: Language,
        epoch: &str,
        writes: &[WriteRow],
        deletes: &[String],
    ) -> Result<()> {
        let lang = language_key(language);
        let mut conn = self.conn.lock().expect("analyzer storage mutex poisoned");
        let tx = conn.transaction()?;

        if !deletes.is_empty() {
            let mut delete_stmt = tx.prepare(
                "DELETE FROM analyzed_files WHERE language = ?1 AND rel_path = ?2",
            )?;
            for path in deletes {
                delete_stmt.execute(params![lang, path])?;
            }
        }

        if !writes.is_empty() {
            let mut upsert = tx.prepare(
                "INSERT INTO analyzed_files \
                   (language, rel_path, mtime_ns, size, epoch, payload) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(language, rel_path) DO UPDATE SET \
                   mtime_ns = excluded.mtime_ns, \
                   size     = excluded.size, \
                   epoch    = excluded.epoch, \
                   payload  = excluded.payload",
            )?;
            for write in writes {
                upsert.execute(params![
                    lang,
                    write.rel_path,
                    write.mtime_ns,
                    write.size,
                    epoch,
                    write.payload,
                ])?;
            }
        }

        tx.execute(
            "INSERT INTO analyzer_epoch (language, epoch) VALUES (?1, ?2) \
             ON CONFLICT(language) DO UPDATE SET epoch = excluded.epoch",
            params![lang, epoch],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Number of persisted file rows for a language. Useful for diagnostics
    /// and for asserting reconcile behavior in tests.
    pub fn row_count(&self, language: Language) -> Result<i64> {
        let lang = language_key(language);
        let conn = self.conn.lock().expect("analyzer storage mutex poisoned");
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM analyzed_files WHERE language = ?1",
            [lang],
            |row| row.get(0),
        )?)
    }
}

fn run_integrity_check(conn: &Connection) -> Result<()> {
    let result: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if result != "ok" {
        return Err(PersistenceError::IntegrityCheck(result));
    }
    Ok(())
}

pub(crate) fn language_key(language: Language) -> &'static str {
    match language {
        Language::None => "none",
        Language::Java => "java",
        Language::Go => "go",
        Language::Cpp => "cpp",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::Php => "php",
        Language::Scala => "scala",
        Language::CSharp => "csharp",
    }
}
