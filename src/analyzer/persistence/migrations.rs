//! Sequential schema migrations for the analyzer SQLite database.
//!
//! Migrations are applied in order from `(current user_version)+1 .. LATEST`,
//! each in its own transaction. After every migration runs the new version
//! is written to `PRAGMA user_version`, so a process killed mid-upgrade
//! resumes from where it left off on next open.

use rusqlite::{Connection, Result, Transaction};

pub(crate) const LATEST_SCHEMA_VERSION: u32 = 2;

pub(crate) fn migrate(conn: &mut Connection) -> Result<()> {
    let current: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current > LATEST_SCHEMA_VERSION {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            UnsupportedFutureSchema {
                found: current,
                supported: LATEST_SCHEMA_VERSION,
            },
        )));
    }

    for version in (current + 1)..=LATEST_SCHEMA_VERSION {
        let tx = conn.transaction()?;
        apply_version(&tx, version)?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(())
}

fn apply_version(tx: &Transaction<'_>, version: u32) -> Result<()> {
    match version {
        1 => apply_v1(tx),
        2 => apply_v2(tx),
        other => Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            UnknownSchemaVersion { version: other },
        ))),
    }
}

fn apply_v1(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE schema_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE analyzer_epoch (
            language TEXT PRIMARY KEY,
            epoch    TEXT NOT NULL
        );

        CREATE TABLE analyzed_files (
            language TEXT NOT NULL,
            rel_path TEXT NOT NULL,
            mtime_ns INTEGER NOT NULL,
            size     INTEGER NOT NULL,
            epoch    TEXT NOT NULL,
            payload  BLOB NOT NULL,
            PRIMARY KEY (language, rel_path)
        );
        "#,
    )?;
    tx.execute(
        "INSERT INTO schema_meta(key, value) VALUES (?1, ?2)",
        rusqlite::params!["created_at", chrono_seconds_now().to_string()],
    )?;
    Ok(())
}

/// v2: disk-backed symbol/FQN index for cold-start search.
///
/// Adds a `symbols` table populated alongside `analyzed_files`, plus two
/// FTS5 virtual tables that index `fq_name` and `short_name`:
///
/// - `symbols_fts` uses the unicode61 tokenizer with `.`, `:`, and `_` as
///   extra separators, so `foo.bar.Baz`, `Foo::Bar`, and `my_function` all
///   tokenize into their identifier parts. Good for whole-token / FQN
///   queries.
/// - `symbols_fts_tri` uses the trigram tokenizer for substring/contains
///   queries.
///
/// Both FTS tables are kept in sync with `symbols` via row triggers; the
/// commit path also explicitly deletes per-file symbol rows before
/// re-inserting them, so the FTS index never carries stale entries from a
/// previous analysis of the same file.
///
/// Why the epoch wipe at the end: `analyzed_files` rows from a v1 build
/// are still around but their owning files have no `symbols` rows yet.
/// The next analyzer open compares the persisted epoch to a freshly
/// computed one. If they happen to match (same parser fingerprint, same
/// .scm files), reconcile would land every workspace file in
/// `clean_hydrated`, no `WriteRow`s would fire, and the new symbol index
/// would stay silently empty. Wiping the epoch forces a one-time
/// dirty-mark of every file on first open after migration so the symbol
/// index gets populated.
fn apply_v2(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE symbols (
            language     TEXT NOT NULL,
            rel_path     TEXT NOT NULL,
            fq_name      TEXT NOT NULL,
            short_name   TEXT NOT NULL,
            package_name TEXT NOT NULL,
            kind         TEXT NOT NULL,
            signature    TEXT,
            synthetic    INTEGER NOT NULL,
            start_byte   INTEGER NOT NULL,
            end_byte     INTEGER NOT NULL,
            start_line   INTEGER NOT NULL,
            end_line     INTEGER NOT NULL,
            PRIMARY KEY (language, rel_path, fq_name, kind, start_byte),
            FOREIGN KEY (language, rel_path)
                REFERENCES analyzed_files(language, rel_path)
                ON DELETE CASCADE
        );

        CREATE INDEX symbols_by_file ON symbols(language, rel_path);

        CREATE VIRTUAL TABLE symbols_fts USING fts5(
            fq_name,
            short_name,
            tokenize = "unicode61 separators '._:'"
        );

        CREATE VIRTUAL TABLE symbols_fts_tri USING fts5(
            fq_name,
            short_name,
            tokenize = "trigram"
        );

        CREATE TRIGGER symbols_ai AFTER INSERT ON symbols BEGIN
            INSERT INTO symbols_fts(rowid, fq_name, short_name)
                VALUES (new.rowid, new.fq_name, new.short_name);
            INSERT INTO symbols_fts_tri(rowid, fq_name, short_name)
                VALUES (new.rowid, new.fq_name, new.short_name);
        END;

        CREATE TRIGGER symbols_ad AFTER DELETE ON symbols BEGIN
            DELETE FROM symbols_fts WHERE rowid = old.rowid;
            DELETE FROM symbols_fts_tri WHERE rowid = old.rowid;
        END;
        "#,
    )?;
    // See module-level rationale: this guarantees the next reconcile
    // dirty-marks every v1 file so the new symbol index gets populated.
    tx.execute("DELETE FROM analyzer_epoch", [])?;
    Ok(())
}

fn chrono_seconds_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug)]
struct UnsupportedFutureSchema {
    found: u32,
    supported: u32,
}

impl std::fmt::Display for UnsupportedFutureSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "analyzer database schema version {} is newer than the highest version this build supports ({}); refusing to open",
            self.found, self.supported
        )
    }
}

impl std::error::Error for UnsupportedFutureSchema {}

#[derive(Debug)]
struct UnknownSchemaVersion {
    version: u32,
}

impl std::fmt::Display for UnknownSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no migration registered for schema version {}",
            self.version
        )
    }
}

impl std::error::Error for UnknownSchemaVersion {}
