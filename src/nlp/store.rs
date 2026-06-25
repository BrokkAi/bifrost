use git2::Repository;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const DB_FILE_NAME: &str = "semantic_cache.db";
const DB_DIR_NAME: &str = ".brokk";
const LATEST_SCHEMA_VERSION: i64 = 1;
const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);
const META_SCHEMA_VERSION: &str = "schema_version";
const META_EMBED_FINGERPRINT: &str = "embed_fingerprint";
const META_BM25_TOKENIZER_VERSION: &str = "bm25_tokenizer_version";
const META_CHUNKER_VERSION: &str = "chunker_version";
const META_LAST_GC_AT: &str = "last_gc_at";
const SQLITE_IN_LIMIT: usize = 500;

/// Resolve the per-primary-repo cache path. Worktrees collapse to the primary
/// repo so every checkout of one repo shares a single content-addressed cache.
///
/// Callers must already have gated on git availability (semantic search is git
/// only); for a non-repo path this still returns a path, but the indexer is
/// never started there.
pub fn semantic_db_path(workspace_root: &Path) -> PathBuf {
    let primary_root = Repository::discover(workspace_root)
        .ok()
        .and_then(|repo| {
            if repo.is_bare() {
                return None;
            }
            if repo.is_worktree() {
                let common = repo.commondir();
                return common.parent().map(Path::to_path_buf);
            }
            repo.workdir().map(Path::to_path_buf)
        })
        .unwrap_or_else(|| workspace_root.to_path_buf());
    primary_root.join(DB_DIR_NAME).join(DB_FILE_NAME)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(String);

impl StoreError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::new(format!("semantic store I/O error: {err}"))
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::new(format!("semantic store SQLite error: {err}"))
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct SemanticStore {
    conn: Mutex<Connection>,
}

/// A single chunk's persisted metadata, written by `put_blob`. The chunk's own
/// text and the parent summary's text are NOT stored (re-derived from git on a
/// fingerprint/chunker change); only the content-hash keys into the vector pools
/// plus the display metadata and precomputed bm25 tokens are kept.
#[derive(Debug, Clone)]
pub struct BlobChunkIn<'a> {
    pub chunk_ord: i64,
    pub kind: &'a str,
    pub symbol: Option<&'a str>,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub fts_tokens: &'a str,
    /// `hash(text)` — key into `component_vectors`.
    pub hash: [u8; 32],
    /// `hash(parent_summary)` — key into `component_vectors` and `blob_summaries`.
    pub parent_summary_hash: Option<[u8; 32]>,
    /// `compose(...)` — key into `vectors` (the searchable vector).
    pub composed_hash: [u8; 32],
}

/// A chunk row read back for active-index construction. Carries `blob_oid` so the
/// caller can attach the per-worktree path; `text`/keys for embedding are not
/// needed here (the vectors already live in the cache, keyed by `composed_hash`).
#[derive(Debug, Clone, PartialEq)]
pub struct BlobChunkRow {
    pub blob_oid: String,
    pub chunk_ord: i64,
    pub kind: String,
    pub symbol: Option<String>,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub fts_tokens: String,
    pub composed_hash: [u8; 32],
}

/// One row streamed by `scan_active_vectors`: a searchable vector (as fastrq code
/// bytes, see [`super::quant`]) and its key.
#[derive(Debug, Clone, PartialEq)]
pub struct VectorRow {
    pub composed_hash: [u8; 32],
    pub code: Vec<u8>,
}

impl SemanticStore {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        conn.busy_timeout(Duration::from_millis(5000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;

        migrate(&mut conn)?;
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS active_chunks(
                 composed_hash BLOB PRIMARY KEY
             ) WITHOUT ROWID;",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Wipe all cached content when the embedding fingerprint or text-derivation
    /// versions change. Because chunk/summary text is not persisted, a version
    /// bump means the cache must be rebuilt from git, so we drop everything and
    /// let the next full build re-materialize. Returns whether a wipe happened.
    pub fn ensure_index_compatible(
        &self,
        fingerprint: &str,
        chunker_version: &str,
        bm25_tokenizer_version: &str,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let stored_fp = meta_value_tx(&tx, META_EMBED_FINGERPRINT)?;
        let stored_chunker = meta_value_tx(&tx, META_CHUNKER_VERSION)?;
        let stored_bm25 = meta_value_tx(&tx, META_BM25_TOKENIZER_VERSION)?;
        let first_run = stored_fp.is_none() && stored_chunker.is_none() && stored_bm25.is_none();
        let matches = stored_fp.as_deref() == Some(fingerprint)
            && stored_chunker.as_deref() == Some(chunker_version)
            && stored_bm25.as_deref() == Some(bm25_tokenizer_version);
        let wiped = if first_run || matches {
            false
        } else {
            // blob_chunks cascade from blobs.
            tx.execute("DELETE FROM blobs", [])?;
            tx.execute("DELETE FROM blob_summaries", [])?;
            tx.execute("DELETE FROM vectors", [])?;
            tx.execute("DELETE FROM component_vectors", [])?;
            true
        };
        set_meta_value_tx(&tx, META_EMBED_FINGERPRINT, fingerprint)?;
        set_meta_value_tx(&tx, META_CHUNKER_VERSION, chunker_version)?;
        set_meta_value_tx(&tx, META_BM25_TOKENIZER_VERSION, bm25_tokenizer_version)?;
        tx.commit()?;
        Ok(wiped)
    }

    // ---- materialization (write path) ------------------------------------

    /// Which of `oids` are not yet materialized in the cache.
    pub fn missing_blobs(&self, oids: &[String]) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut stmt = conn.prepare("SELECT 1 FROM blobs WHERE blob_oid = ?1 LIMIT 1")?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for oid in oids {
            if !seen.insert(oid.clone()) {
                continue;
            }
            let exists = stmt.query_row([oid], |_| Ok(())).optional()?.is_some();
            if !exists {
                out.push(oid.clone());
            }
        }
        Ok(out)
    }

    pub fn missing_component_hashes(&self, hashes: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        self.missing_hashes("component_vectors", "hash", hashes)
    }

    pub fn missing_composed_hashes(&self, hashes: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        self.missing_hashes("vectors", "composed_hash", hashes)
    }

    /// Component vectors are stored as fastrq codes; decode them (lossily) back to
    /// f32 for re-composition.
    pub fn component_vectors(&self, hashes: &[[u8; 32]]) -> Result<HashMap<[u8; 32], Vec<f32>>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut select = conn.prepare("SELECT vector FROM component_vectors WHERE hash = ?1")?;
        let mut out = HashMap::new();
        let mut seen = HashSet::new();
        for hash in hashes {
            if !seen.insert(*hash) {
                continue;
            }
            let code: Option<Vec<u8>> = select
                .query_row(params![hash.as_slice()], |row| row.get(0))
                .optional()?;
            if let Some(code) = code {
                out.insert(
                    *hash,
                    super::quant::decode_vector(&code).map_err(StoreError::new)?,
                );
            }
        }
        Ok(out)
    }

    pub fn upsert_component_vectors(&self, items: &[([u8; 32], Vec<f32>)]) -> Result<()> {
        self.upsert_codes("component_vectors", "hash", items)
    }

    pub fn upsert_composed_vectors(&self, items: &[([u8; 32], Vec<f32>)]) -> Result<()> {
        self.upsert_codes("vectors", "composed_hash", items)
    }

    /// Encode each vector to a fastrq 8-bit code (~4x smaller than f32; see
    /// [`super::quant`]) and persist it. `dim` keeps the original f32 dimension for
    /// diagnostics; the searchable/component blob is the code, never raw f32.
    fn upsert_codes(
        &self,
        table: &str,
        key_col: &str,
        items: &[([u8; 32], Vec<f32>)],
    ) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let sql = format!(
            "INSERT INTO {table}({key_col}, dim, vector) VALUES(?1, ?2, ?3)
             ON CONFLICT({key_col}) DO NOTHING"
        );
        let mut stmt = tx.prepare(&sql)?;
        for (key, vector) in items {
            let code = super::quant::encode_vector(vector);
            stmt.execute(params![key.as_slice(), vector.len() as i64, code])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    /// Replace one blob's materialized chunks (and intern its parent summaries).
    /// The component/composed vectors must already be upserted.
    pub fn put_blob(
        &self,
        blob_oid: &str,
        language: Option<&str>,
        chunks: &[BlobChunkIn<'_>],
    ) -> Result<()> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO blobs(blob_oid, language) VALUES(?1, ?2)
             ON CONFLICT(blob_oid) DO UPDATE SET
                 language = excluded.language,
                 materialized_at = datetime('now')",
            params![blob_oid, language],
        )?;
        tx.execute("DELETE FROM blob_chunks WHERE blob_oid = ?1", [blob_oid])?;

        let mut intern_summary =
            tx.prepare("INSERT INTO blob_summaries(hash) VALUES(?1) ON CONFLICT(hash) DO NOTHING")?;
        let mut select_summary =
            tx.prepare("SELECT blob_summary_id FROM blob_summaries WHERE hash = ?1")?;
        let mut insert_chunk = tx.prepare(
            "INSERT INTO blob_chunks(
                 blob_oid, chunk_ord, kind, symbol, start_line, end_line,
                 fts_tokens, hash, parent_summary_id, composed_hash
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        let mut summary_ids: HashMap<[u8; 32], i64> = HashMap::new();
        for chunk in chunks {
            let parent_summary_id = match chunk.parent_summary_hash {
                None => None,
                Some(hash) => {
                    let id = match summary_ids.get(&hash) {
                        Some(id) => *id,
                        None => {
                            intern_summary.execute(params![hash.as_slice()])?;
                            let id: i64 = select_summary
                                .query_row(params![hash.as_slice()], |row| row.get(0))?;
                            summary_ids.insert(hash, id);
                            id
                        }
                    };
                    Some(id)
                }
            };
            insert_chunk.execute(params![
                blob_oid,
                chunk.chunk_ord,
                chunk.kind,
                chunk.symbol,
                chunk.start_line,
                chunk.end_line,
                chunk.fts_tokens,
                chunk.hash.as_slice(),
                parent_summary_id,
                chunk.composed_hash.as_slice(),
            ])?;
        }
        drop(intern_summary);
        drop(select_summary);
        drop(insert_chunk);
        tx.commit()?;
        Ok(())
    }

    // ---- active-index construction (read path) ---------------------------

    /// All chunk rows for the given blob OIDs, for building the in-memory active
    /// index. Returned rows carry `blob_oid`; the caller groups + attaches paths.
    pub fn chunks_for_oids(&self, oids: &[String]) -> Result<Vec<BlobChunkRow>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let unique: Vec<&String> = oids.iter().filter(|oid| seen.insert(*oid)).collect();
        for batch in unique.chunks(SQLITE_IN_LIMIT) {
            let placeholders = std::iter::repeat_n("?", batch.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT blob_oid, chunk_ord, kind, symbol, start_line, end_line,
                        fts_tokens, composed_hash
                 FROM blob_chunks
                 WHERE blob_oid IN ({placeholders})
                 ORDER BY blob_oid, chunk_ord"
            );
            let mut stmt = conn.prepare(&sql)?;
            let params_iter = batch
                .iter()
                .map(|oid| rusqlite::types::Value::Text((*oid).clone()));
            let mut rows = stmt.query(rusqlite::params_from_iter(params_iter))?;
            while let Some(row) = rows.next()? {
                out.push(BlobChunkRow {
                    blob_oid: row.get(0)?,
                    chunk_ord: row.get(1)?,
                    kind: row.get(2)?,
                    symbol: row.get(3)?,
                    start_line: row.get(4)?,
                    end_line: row.get(5)?,
                    fts_tokens: row.get(6)?,
                    composed_hash: decode_key_blob(row.get::<_, Vec<u8>>(7)?)?,
                });
            }
        }
        Ok(out)
    }

    /// Set the connection-local active set used to scope `scan_active_vectors`.
    /// `active_chunks` is a TEMP table (per connection), so concurrent worktree
    /// processes on the shared DB file never collide.
    pub fn set_active_composed_hashes(&self, hashes: &HashSet<[u8; 32]>) -> Result<()> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM active_chunks", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO active_chunks(composed_hash) VALUES(?1)
                 ON CONFLICT(composed_hash) DO NOTHING",
            )?;
            for hash in hashes {
                stmt.execute(params![hash.as_slice()])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Incrementally add composed hashes to the active set (watcher add path).
    pub fn add_active_composed(&self, hashes: &[[u8; 32]]) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO active_chunks(composed_hash) VALUES(?1)
                 ON CONFLICT(composed_hash) DO NOTHING",
            )?;
            for hash in hashes {
                stmt.execute(params![hash.as_slice()])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Incrementally drop composed hashes from the active set (watcher evict path).
    pub fn remove_active_composed(&self, hashes: &[[u8; 32]]) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare("DELETE FROM active_chunks WHERE composed_hash = ?1")?;
            for hash in hashes {
                stmt.execute(params![hash.as_slice()])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Stream the active set's searchable vectors in batches. Producer side of
    /// the parallel vector scan: consumers score cosine off-thread.
    pub fn scan_active_vectors(
        &self,
        batch_size: usize,
        visit: &mut dyn FnMut(Vec<VectorRow>),
    ) -> Result<()> {
        let effective_batch = batch_size.max(1);
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT v.composed_hash, v.vector
             FROM vectors v
             JOIN active_chunks a ON a.composed_hash = v.composed_hash",
        )?;
        let mut rows = stmt.query([])?;
        let mut batch = Vec::with_capacity(effective_batch);
        while let Some(row) = rows.next()? {
            batch.push(VectorRow {
                composed_hash: decode_key_blob(row.get::<_, Vec<u8>>(0)?)?,
                code: row.get::<_, Vec<u8>>(1)?,
            });
            if batch.len() == effective_batch {
                visit(std::mem::take(&mut batch));
                batch = Vec::with_capacity(effective_batch);
            }
        }
        if !batch.is_empty() {
            visit(batch);
        }
        Ok(())
    }

    // ---- garbage collection ----------------------------------------------

    /// Drop everything no longer reachable from git (or held by a worktree's
    /// uncommitted working set). `live` is the union of reachable blob OIDs and
    /// currently-checked-out dirty/untracked OIDs.
    pub fn gc(&self, live: &HashSet<String>) -> Result<()> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS gc_live(oid TEXT PRIMARY KEY) WITHOUT ROWID;
             DELETE FROM gc_live;",
        )?;
        {
            let mut stmt =
                tx.prepare("INSERT INTO gc_live(oid) VALUES(?1) ON CONFLICT(oid) DO NOTHING")?;
            for oid in live {
                stmt.execute([oid])?;
            }
        }
        // blob_chunks cascade from blobs.
        tx.execute(
            "DELETE FROM blobs WHERE blob_oid NOT IN (SELECT oid FROM gc_live)",
            [],
        )?;
        tx.execute(
            "DELETE FROM vectors
             WHERE composed_hash NOT IN (SELECT composed_hash FROM blob_chunks)",
            [],
        )?;
        tx.execute(
            "DELETE FROM blob_summaries
             WHERE blob_summary_id NOT IN (
                 SELECT parent_summary_id FROM blob_chunks
                 WHERE parent_summary_id IS NOT NULL
             )",
            [],
        )?;
        tx.execute(
            "DELETE FROM component_vectors
             WHERE hash NOT IN (
                 SELECT hash FROM blob_chunks
                 UNION SELECT hash FROM blob_summaries
             )",
            [],
        )?;
        tx.execute("DROP TABLE gc_live", [])?;
        set_meta_value_tx(&tx, META_LAST_GC_AT, &now_unix_seconds().to_string())?;
        tx.commit()?;
        conn.pragma_update(None, "incremental_vacuum", 0)?;
        Ok(())
    }

    /// Seconds since the last `gc`, or `None` if never run.
    pub fn seconds_since_gc(&self) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let stored: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_LAST_GC_AT],
                |row| row.get(0),
            )
            .optional()?;
        Ok(stored
            .and_then(|value| value.parse::<i64>().ok())
            .map(|at| now_unix_seconds() - at))
    }

    fn missing_hashes(
        &self,
        table: &str,
        key_col: &str,
        hashes: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let sql = format!("SELECT 1 FROM {table} WHERE {key_col} = ?1 LIMIT 1");
        let mut stmt = conn.prepare(&sql)?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for hash in hashes {
            if !seen.insert(*hash) {
                continue;
            }
            let exists = stmt
                .query_row(params![hash.as_slice()], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                out.push(*hash);
            }
        }
        Ok(out)
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    assert_sqlite_version(conn)?;
    let current = schema_version(conn)?;
    if current != 0 && current != LATEST_SCHEMA_VERSION {
        // The index is a rebuildable cache: on any schema mismatch, drop and
        // recreate rather than carry migration code.
        recreate_schema(conn)?;
        return Ok(());
    }
    if current == 0 {
        let tx = conn.transaction()?;
        create_schema(&tx)?;
        set_meta_value_tx(&tx, META_SCHEMA_VERSION, &LATEST_SCHEMA_VERSION.to_string())?;
        tx.commit()?;
    }
    Ok(())
}

fn recreate_schema(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "DROP TABLE IF EXISTS blob_chunks;
         DROP TABLE IF EXISTS blob_summaries;
         DROP TABLE IF EXISTS blobs;
         DROP TABLE IF EXISTS vectors;
         DROP TABLE IF EXISTS component_vectors;
         DROP TABLE IF EXISTS meta;",
    )?;
    create_schema(&tx)?;
    set_meta_value_tx(&tx, META_SCHEMA_VERSION, &LATEST_SCHEMA_VERSION.to_string())?;
    tx.commit()?;
    Ok(())
}

fn create_schema(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);

        CREATE TABLE blobs(
          blob_oid        TEXT PRIMARY KEY,
          language        TEXT,
          materialized_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE blob_summaries(
          blob_summary_id INTEGER PRIMARY KEY,
          hash            BLOB NOT NULL UNIQUE
        );

        CREATE TABLE blob_chunks(
          blob_oid          TEXT NOT NULL REFERENCES blobs(blob_oid) ON DELETE CASCADE,
          chunk_ord         INTEGER NOT NULL,
          kind              TEXT NOT NULL,
          symbol            TEXT,
          start_line        INTEGER,
          end_line          INTEGER,
          fts_tokens        TEXT NOT NULL,
          hash              BLOB NOT NULL,
          parent_summary_id INTEGER REFERENCES blob_summaries(blob_summary_id),
          composed_hash     BLOB NOT NULL,
          PRIMARY KEY(blob_oid, chunk_ord)
        ) WITHOUT ROWID;
        CREATE INDEX blob_chunks_by_hash     ON blob_chunks(hash);
        CREATE INDEX blob_chunks_by_parent   ON blob_chunks(parent_summary_id);
        CREATE INDEX blob_chunks_by_composed ON blob_chunks(composed_hash);

        CREATE TABLE component_vectors(
          hash   BLOB PRIMARY KEY,
          dim    INTEGER NOT NULL,
          vector BLOB NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE vectors(
          composed_hash BLOB PRIMARY KEY,
          dim           INTEGER NOT NULL,
          vector        BLOB NOT NULL
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

fn schema_version(conn: &Connection) -> Result<i64> {
    let meta_exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if meta_exists.is_none() {
        return Ok(0);
    }
    let version = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [META_SCHEMA_VERSION],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    version
        .as_deref()
        .unwrap_or("0")
        .parse::<i64>()
        .map_err(|err| StoreError::new(format!("invalid semantic store schema version: {err}")))
}

fn meta_value_tx(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
) -> std::result::Result<Option<String>, rusqlite::Error> {
    tx.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .optional()
}

fn set_meta_value_tx(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    value: &str,
) -> std::result::Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn assert_sqlite_version(conn: &Connection) -> Result<()> {
    let version: String = conn.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let parsed = parse_sqlite_version(&version).ok_or_else(|| {
        StoreError::new(format!(
            "unable to parse sqlite_version() output: {version}"
        ))
    })?;
    if parsed < SQLITE_MIN_VERSION {
        return Err(StoreError::new(format!(
            "semantic store requires sqlite >= {}.{}.{} but found {version}",
            SQLITE_MIN_VERSION.0, SQLITE_MIN_VERSION.1, SQLITE_MIN_VERSION.2
        )));
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

fn decode_key_blob(blob: Vec<u8>) -> Result<[u8; 32]> {
    blob.try_into().map_err(|value: Vec<u8>| {
        StoreError::new(format!(
            "expected 32-byte key blob, got {} bytes",
            value.len()
        ))
    })
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn open_temp() -> (tempfile::TempDir, SemanticStore) {
        let temp = tempfile::TempDir::new().unwrap();
        let store = SemanticStore::open(&temp.path().join("semantic_cache.db")).unwrap();
        (temp, store)
    }

    fn chunk(
        ord: i64,
        hash: [u8; 32],
        composed: [u8; 32],
        parent: Option<[u8; 32]>,
    ) -> BlobChunkIn<'static> {
        BlobChunkIn {
            chunk_ord: ord,
            kind: if ord == 0 { "file_summary" } else { "function" },
            symbol: if ord == 0 {
                None
            } else {
                Some("pkg.Cls.method")
            },
            start_line: Some(ord),
            end_line: Some(ord + 5),
            fts_tokens: "alpha beta gamma",
            hash,
            parent_summary_hash: parent,
            composed_hash: composed,
        }
    }

    fn run_git<const N: usize>(dir: &Path, args: [&str; N]) {
        let status = Command::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[test]
    fn put_blob_roundtrips_chunks_and_dedupes_summaries() {
        let (_temp, store) = open_temp();
        let parent = [9u8; 32];
        store
            .upsert_component_vectors(&[([1; 32], vec![1.0, 0.0]), (parent, vec![0.0, 1.0])])
            .unwrap();
        store
            .upsert_composed_vectors(&[([5; 32], vec![1.0, 0.0]), ([6; 32], vec![0.0, 1.0])])
            .unwrap();
        store
            .put_blob(
                "oid_a",
                Some("rust"),
                &[
                    chunk(0, [2; 32], [5; 32], None),
                    chunk(1, [1; 32], [6; 32], Some(parent)),
                ],
            )
            .unwrap();

        let rows = store.chunks_for_oids(&["oid_a".to_string()]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, "file_summary");
        assert_eq!(rows[1].symbol.as_deref(), Some("pkg.Cls.method"));
        assert_eq!(rows[1].composed_hash, [6; 32]);

        assert!(
            store
                .missing_blobs(&["oid_a".into(), "oid_b".into()])
                .unwrap()
                == vec!["oid_b".to_string()]
        );
    }

    #[test]
    fn scan_active_vectors_respects_active_set() {
        let (_temp, store) = open_temp();
        store
            .upsert_composed_vectors(&[([5; 32], vec![1.0, 0.0]), ([6; 32], vec![0.0, 1.0])])
            .unwrap();
        store
            .put_blob("oid_a", None, &[chunk(1, [1; 32], [5; 32], None)])
            .unwrap();

        let active: HashSet<[u8; 32]> = [[5u8; 32]].into_iter().collect();
        store.set_active_composed_hashes(&active).unwrap();

        let mut seen = Vec::new();
        store
            .scan_active_vectors(8, &mut |batch| seen.extend(batch))
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].composed_hash, [5; 32]);
    }

    #[test]
    fn gc_drops_unreachable_blobs_and_orphans() {
        let (_temp, store) = open_temp();
        store
            .upsert_component_vectors(&[([1; 32], vec![1.0, 0.0])])
            .unwrap();
        store
            .upsert_composed_vectors(&[([5; 32], vec![1.0, 0.0])])
            .unwrap();
        store
            .put_blob("oid_keep", None, &[chunk(1, [1; 32], [5; 32], None)])
            .unwrap();
        store
            .put_blob("oid_drop", None, &[chunk(1, [1; 32], [5; 32], None)])
            .unwrap();

        let live: HashSet<String> = ["oid_keep".to_string()].into_iter().collect();
        store.gc(&live).unwrap();

        assert_eq!(
            store.chunks_for_oids(&["oid_drop".into()]).unwrap().len(),
            0
        );
        assert_eq!(
            store.chunks_for_oids(&["oid_keep".into()]).unwrap().len(),
            1
        );
        // The shared vector/component are still referenced by oid_keep.
        assert!(
            store
                .missing_composed_hashes(&[[5; 32]])
                .unwrap()
                .is_empty()
        );
        assert!(store.seconds_since_gc().unwrap().is_some());
    }

    #[test]
    fn version_change_wipes_cache() {
        let (_temp, store) = open_temp();
        assert!(!store.ensure_index_compatible("fp1", "ck1", "bm1").unwrap());
        store
            .upsert_composed_vectors(&[([5; 32], vec![1.0, 0.0])])
            .unwrap();
        store
            .put_blob("oid_a", None, &[chunk(1, [1; 32], [5; 32], None)])
            .unwrap();

        assert!(store.ensure_index_compatible("fp2", "ck1", "bm1").unwrap());
        assert_eq!(store.chunks_for_oids(&["oid_a".into()]).unwrap().len(), 0);
        assert!(
            !store
                .missing_composed_hashes(&[[5; 32]])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn semantic_db_path_uses_primary_root_for_linked_worktree() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        std::fs::create_dir_all(&repo_root).unwrap();
        run_git(&repo_root, ["init"]);
        run_git(&repo_root, ["config", "user.email", "test@example.com"]);
        run_git(&repo_root, ["config", "user.name", "Test User"]);
        std::fs::write(repo_root.join("tracked.txt"), "hello\n").unwrap();
        run_git(&repo_root, ["add", "tracked.txt"]);
        run_git(&repo_root, ["commit", "-m", "init"]);

        let worktree_root = temp.path().join("linked");
        run_git(
            &repo_root,
            ["worktree", "add", worktree_root.to_str().unwrap(), "HEAD"],
        );

        let actual = semantic_db_path(&worktree_root);
        assert_eq!(
            actual.file_name().and_then(|n| n.to_str()),
            Some(DB_FILE_NAME)
        );
        let actual_root = actual.parent().and_then(Path::parent).unwrap();
        assert_eq!(
            std::fs::canonicalize(actual_root).unwrap(),
            std::fs::canonicalize(&repo_root).unwrap()
        );
    }
}
