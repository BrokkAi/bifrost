//! Sequential schema migrations for the analyzer SQLite database.
//!
//! Migrations are applied in order from `(current user_version)+1 .. LATEST`,
//! each in its own transaction. After every migration runs the new version
//! is written to `PRAGMA user_version`, so a process killed mid-upgrade
//! resumes from where it left off on next open.

use rusqlite::{Connection, Result, Transaction};

pub(crate) const LATEST_SCHEMA_VERSION: u32 = 1;

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
