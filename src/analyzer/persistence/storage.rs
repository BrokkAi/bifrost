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

/// Resolve the default analyzer DB path for `project_root`, refusing to use it
/// when the cache directory or the DB file is a symlink. Persisting through a
/// symlink would let an attacker (or an accidental link) redirect writes
/// outside the project, so we disable persistence and fall back to a full
/// rebuild instead. Returns `None` when persistence should be skipped.
pub fn safe_default_db_path(project_root: &Path) -> Option<PathBuf> {
    let cache_dir = project_root.join(DEFAULT_CACHE_DIR);
    if is_symlink(&cache_dir) {
        eprintln!(
            "[bifrost] disabling analyzer storage for {}: cache directory is a symlink",
            project_root.display()
        );
        return None;
    }

    let db_path = default_db_path(project_root);
    if is_symlink(&db_path) {
        eprintln!(
            "[bifrost] disabling analyzer storage for {}: cache database is a symlink",
            project_root.display()
        );
        return None;
    }
    Some(db_path)
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
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

/// Inputs to `commit_reconcile`: a write replaces (or inserts) one row in
/// `analyzed_files` and replaces all of that file's `symbols` rows with the
/// supplied list.
#[derive(Debug)]
pub struct WriteRow {
    pub rel_path: String,
    pub mtime_ns: i64,
    pub size: i64,
    pub payload: Vec<u8>,
    pub symbols: Vec<SymbolRow>,
}

/// One row in the `symbols` table. The `language` column is supplied at
/// commit time and the FK to `analyzed_files(language, rel_path)` is
/// resolved via the parent `WriteRow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRow {
    pub fq_name: String,
    pub short_name: String,
    pub package_name: String,
    pub kind: String,
    pub signature: Option<String>,
    pub synthetic: bool,
    pub start_byte: i64,
    pub end_byte: i64,
    pub start_line: i64,
    pub end_line: i64,
}

/// One row materialized from a `symbols` FTS5 query result. Carries the
/// `rel_path` of the owning file so the caller can rebuild a `ProjectFile`
/// using the analyzer's project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolHit {
    pub rel_path: String,
    pub symbol: SymbolRow,
}

/// Which FTS5 index to consult for a query.
///
/// `Substring` uses the trigram-tokenized index, which matches characters
/// regardless of word boundaries — closest in semantics to the existing
/// regex-based `search_definitions`. *Caveat:* FTS5's trigram tokenizer
/// emits no tokens for inputs shorter than three characters, so 1- and
/// 2-character `Substring` queries always return zero hits. Callers that
/// need full substring recall on short patterns must fall back to an
/// in-memory regex scan.
///
/// `Token` uses the unicode61 index, which splits FQNs on `.`, `:`, and
/// `_`; useful when you want to hit whole identifier components.
/// `Prefix` is `Token` with a trailing `*` — anchored at a token start,
/// useful for "everything starting with `Foo`" queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolQueryMode {
    Substring,
    Token,
    Prefix,
}

/// Default cap on persisted symbol search results. FTS5 ranks by bm25; a
/// few hundred top hits is plenty for an interactive query and protects
/// callers on large repos from accidentally pulling tens of thousands of
/// rows.
pub const DEFAULT_SYMBOL_QUERY_LIMIT: usize = 500;

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
    /// replace each written file's `symbols` rows with the supplied list,
    /// delete every path in `deletes`, and bump the analyzer epoch.
    ///
    /// For each write we explicitly clear the file's existing symbol rows
    /// before re-inserting; the AFTER DELETE / AFTER INSERT triggers on
    /// `symbols` keep the FTS5 indexes in sync. We don't rely on the
    /// `analyzed_files` FK CASCADE alone here because mixing CASCADE with
    /// FTS5 sync triggers across SQLite versions is fragile.
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
            let mut delete_symbols =
                tx.prepare("DELETE FROM symbols WHERE language = ?1 AND rel_path = ?2")?;
            let mut delete_file =
                tx.prepare("DELETE FROM analyzed_files WHERE language = ?1 AND rel_path = ?2")?;
            for path in deletes {
                delete_symbols.execute(params![lang, path])?;
                delete_file.execute(params![lang, path])?;
            }
        }

        if !writes.is_empty() {
            let mut delete_symbols =
                tx.prepare("DELETE FROM symbols WHERE language = ?1 AND rel_path = ?2")?;
            let mut upsert_file = tx.prepare(
                "INSERT INTO analyzed_files \
                   (language, rel_path, mtime_ns, size, epoch, payload) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(language, rel_path) DO UPDATE SET \
                   mtime_ns = excluded.mtime_ns, \
                   size     = excluded.size, \
                   epoch    = excluded.epoch, \
                   payload  = excluded.payload",
            )?;
            // No `OR IGNORE`: `delete_symbols` ran for this rel_path
            // immediately above, so any PK collision would mean
            // `extract_symbols` emitted two rows with identical
            // (language, rel_path, fq_name, kind, start_byte) for the
            // same file — an analyzer bug we want to surface.
            let mut insert_symbol = tx.prepare(
                "INSERT INTO symbols \
                   (language, rel_path, fq_name, short_name, package_name, \
                    kind, signature, synthetic, \
                    start_byte, end_byte, start_line, end_line) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            for write in writes {
                delete_symbols.execute(params![lang, write.rel_path])?;
                upsert_file.execute(params![
                    lang,
                    write.rel_path,
                    write.mtime_ns,
                    write.size,
                    epoch,
                    write.payload,
                ])?;
                for sym in &write.symbols {
                    insert_symbol.execute(params![
                        lang,
                        write.rel_path,
                        sym.fq_name,
                        sym.short_name,
                        sym.package_name,
                        sym.kind,
                        sym.signature,
                        sym.synthetic as i64,
                        sym.start_byte,
                        sym.end_byte,
                        sym.start_line,
                        sym.end_line,
                    ])?;
                }
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

    /// Cold-start symbol search: query an FTS5 index on the persisted
    /// `symbols` table without rebuilding the in-memory analyzer. Returns
    /// at most `DEFAULT_SYMBOL_QUERY_LIMIT` matching symbol rows, ordered
    /// by FTS5 bm25 rank (best-first), each tagged with the `rel_path` of
    /// its owning file.
    ///
    /// `pattern` is treated as a literal: FTS5 special characters in the
    /// input are escaped so a user-supplied identifier never accidentally
    /// becomes an operator or column filter.
    pub fn search_symbols(
        &self,
        language: Language,
        pattern: &str,
        mode: SymbolQueryMode,
    ) -> Result<Vec<SymbolHit>> {
        self.search_symbols_with_limit(language, pattern, mode, DEFAULT_SYMBOL_QUERY_LIMIT)
    }

    /// `search_symbols` with an explicit row cap. `0` returns no rows.
    pub fn search_symbols_with_limit(
        &self,
        language: Language,
        pattern: &str,
        mode: SymbolQueryMode,
        limit: usize,
    ) -> Result<Vec<SymbolHit>> {
        self.search_symbols_inner(language, pattern, mode, limit, false)
    }

    /// `search_symbols`, but synthetic rows (e.g. compiler-generated
    /// accessors) are filtered out in SQL — that is, *before* `LIMIT`
    /// applies, so the rank cutoff isn't burned on rows the caller
    /// would have discarded anyway.
    pub fn search_non_synthetic_symbols(
        &self,
        language: Language,
        pattern: &str,
        mode: SymbolQueryMode,
    ) -> Result<Vec<SymbolHit>> {
        self.search_symbols_inner(language, pattern, mode, DEFAULT_SYMBOL_QUERY_LIMIT, true)
    }

    fn search_symbols_inner(
        &self,
        language: Language,
        pattern: &str,
        mode: SymbolQueryMode,
        limit: usize,
        exclude_synthetic: bool,
    ) -> Result<Vec<SymbolHit>> {
        if pattern.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let lang = language_key(language);
        let fts_table = match mode {
            SymbolQueryMode::Substring => "symbols_fts_tri",
            // Prefix uses the same unicode61 index as Token; the trailing
            // `*` in the constructed phrase is what turns it into an
            // FTS5 prefix query.
            SymbolQueryMode::Token | SymbolQueryMode::Prefix => "symbols_fts",
        };
        let phrase = build_fts_phrase(pattern, mode);
        let synthetic_clause = if exclude_synthetic {
            " AND s.synthetic = 0"
        } else {
            ""
        };
        // bm25 default weights treat all columns equally; tweak here if
        // we later want to boost short_name over fq_name.
        let sql = format!(
            "SELECT s.rel_path, s.fq_name, s.short_name, s.package_name, \
                    s.kind, s.signature, s.synthetic, \
                    s.start_byte, s.end_byte, s.start_line, s.end_line \
             FROM {fts_table} f \
             JOIN symbols s ON s.rowid = f.rowid \
             WHERE f.{fts_table} MATCH ?1 AND s.language = ?2{synthetic_clause} \
             ORDER BY rank, s.rel_path, s.fq_name, s.start_byte \
             LIMIT ?3"
        );
        let conn = self.conn.lock().expect("analyzer storage mutex poisoned");
        let mut stmt = conn.prepare(&sql)?;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt.query_map(params![phrase, lang, limit_i64], |row| {
            let synthetic_int: i64 = row.get(6)?;
            Ok(SymbolHit {
                rel_path: row.get(0)?,
                symbol: SymbolRow {
                    fq_name: row.get(1)?,
                    short_name: row.get(2)?,
                    package_name: row.get(3)?,
                    kind: row.get(4)?,
                    signature: row.get(5)?,
                    synthetic: synthetic_int != 0,
                    start_byte: row.get(7)?,
                    end_byte: row.get(8)?,
                    start_line: row.get(9)?,
                    end_line: row.get(10)?,
                },
            })
        })?;
        let mut out = Vec::new();
        for hit in rows {
            out.push(hit?);
        }
        Ok(out)
    }

    /// Number of persisted symbol rows for a language. Diagnostic / test helper.
    pub fn symbol_count(&self, language: Language) -> Result<i64> {
        let lang = language_key(language);
        let conn = self.conn.lock().expect("analyzer storage mutex poisoned");
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM symbols WHERE language = ?1",
            [lang],
            |row| row.get(0),
        )?)
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

/// Build the FTS5 MATCH phrase for a user-supplied pattern.
///
/// The pattern is wrapped in double quotes (with inner double quotes
/// doubled) so FTS5 special characters — `*`, `:`, `^`, `AND`, `NOT`,
/// `OR`, column filters — never escape to operator status. For `Prefix`
/// mode, an unquoted `*` is appended to the phrase, which FTS5
/// interprets as a token-prefix match.
fn build_fts_phrase(pattern: &str, mode: SymbolQueryMode) -> String {
    let escaped = pattern.replace('"', "\"\"");
    match mode {
        SymbolQueryMode::Substring | SymbolQueryMode::Token => format!("\"{escaped}\""),
        SymbolQueryMode::Prefix => format!("\"{escaped}\"*"),
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
        Language::Ruby => "ruby",
    }
}
