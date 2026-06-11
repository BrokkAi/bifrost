use super::keys::{blob_to_vector, vector_to_blob};
use git2::Repository;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const DB_FILE_NAME: &str = "semantic_index.db";
const DB_DIR_NAME: &str = ".brokk";
const LATEST_SCHEMA_VERSION: i64 = 1;
const SQLITE_MIN_VERSION: (u32, u32, u32) = (3, 43, 0);
const META_SCHEMA_VERSION: &str = "schema_version";
const META_EMBED_FINGERPRINT: &str = "embed_fingerprint";
const META_BM25_TOKENIZER_VERSION: &str = "bm25_tokenizer_version";
const META_CHUNKER_VERSION: &str = "chunker_version";
const SQLITE_IN_LIMIT: usize = 500;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileState {
    pub file_hash: [u8; 32],
    pub mtime_ns: i64,
    pub size: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ChunkRowIn<'a> {
    pub chunk_ord: i64,
    pub kind: &'a str,
    pub symbol: Option<&'a str>,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub composed_key: [u8; 32],
    pub text_hash: [u8; 32],
    pub fts_tokens: &'a str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanRow {
    pub file_path: String,
    pub kind_is_summary: bool,
    pub chunk_ord: i64,
    pub vector: Vec<f32>,
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

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn ensure_embed_fingerprint(&self, fingerprint: &str) -> Result<bool> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let stored = meta_value_tx(&tx, META_EMBED_FINGERPRINT)?;
        let wiped = match stored {
            None => false,
            Some(value) if value == fingerprint => false,
            Some(_) => {
                tx.execute("DELETE FROM vectors", [])?;
                tx.execute("DELETE FROM component_vectors", [])?;
                tx.execute("DELETE FROM chunks", [])?;
                tx.execute("DELETE FROM files", [])?;
                true
            }
        };
        set_meta_value_tx(&tx, META_EMBED_FINGERPRINT, fingerprint)?;
        tx.commit()?;
        Ok(wiped)
    }

    pub fn ensure_text_versions(
        &self,
        bm25_tokenizer_version: &str,
        chunker_version: &str,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let stored_bm25 = meta_value_tx(&tx, META_BM25_TOKENIZER_VERSION)?;
        let stored_chunker = meta_value_tx(&tx, META_CHUNKER_VERSION)?;
        let first_run = stored_bm25.is_none() && stored_chunker.is_none();
        let matches = stored_bm25.as_deref() == Some(bm25_tokenizer_version)
            && stored_chunker.as_deref() == Some(chunker_version);
        let wiped = if first_run || matches {
            false
        } else {
            tx.execute("DELETE FROM chunks", [])?;
            tx.execute("DELETE FROM files", [])?;
            tx.execute("DELETE FROM bm25_idx", [])?;
            tx.execute("DELETE FROM bm25_docs", [])?;
            true
        };
        set_meta_value_tx(&tx, META_BM25_TOKENIZER_VERSION, bm25_tokenizer_version)?;
        set_meta_value_tx(&tx, META_CHUNKER_VERSION, chunker_version)?;
        tx.commit()?;
        Ok(wiped)
    }

    pub fn workspace_id(&self, root_path: &str) -> Result<i64> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO workspaces(root_path) VALUES(?1)",
            [root_path],
        )?;
        let id = conn.query_row(
            "SELECT workspace_id FROM workspaces WHERE root_path = ?1",
            [root_path],
            |row| row.get(0),
        )?;
        Ok(id)
    }

    pub fn file_states(&self, workspace_id: i64) -> Result<HashMap<String, FileState>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT file_path, file_hash, mtime_ns, size
             FROM files
             WHERE workspace_id = ?1",
        )?;
        let mut rows = stmt.query([workspace_id])?;
        let mut out = HashMap::new();
        while let Some(row) = rows.next()? {
            out.insert(
                row.get::<_, String>(0)?,
                FileState {
                    file_hash: decode_key_blob(row.get::<_, Vec<u8>>(1)?)?,
                    mtime_ns: row.get(2)?,
                    size: row.get(3)?,
                },
            );
        }
        Ok(out)
    }

    pub fn remove_files(&self, workspace_id: i64, paths: &[String]) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let mut delete_chunks =
            tx.prepare("DELETE FROM chunks WHERE workspace_id = ?1 AND file_path = ?2")?;
        let mut delete_files =
            tx.prepare("DELETE FROM files WHERE workspace_id = ?1 AND file_path = ?2")?;
        for path in paths {
            delete_chunks.execute(params![workspace_id, path])?;
            delete_files.execute(params![workspace_id, path])?;
        }
        drop(delete_chunks);
        drop(delete_files);
        tx.commit()?;
        Ok(())
    }

    pub fn touch_built(&self, workspace_id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        conn.execute(
            "UPDATE workspaces SET last_built_at = ?2 WHERE workspace_id = ?1",
            params![workspace_id, now_unix_seconds()],
        )?;
        Ok(())
    }

    pub fn missing_component_keys(&self, keys: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        self.missing_keys("component_vectors", keys)
    }

    pub fn missing_composed_keys(&self, keys: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        self.missing_keys("vectors", keys)
    }

    pub fn component_vectors(&self, keys: &[[u8; 32]]) -> Result<HashMap<[u8; 32], Vec<f32>>> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let now = now_unix_seconds();
        let mut select = tx.prepare("SELECT vector FROM component_vectors WHERE key = ?1")?;
        let mut update =
            tx.prepare("UPDATE component_vectors SET last_used_at = ?2 WHERE key = ?1")?;
        let mut out = HashMap::new();
        let mut seen = HashSet::new();
        for key in keys {
            if !seen.insert(*key) {
                continue;
            }
            let vector_blob: Option<Vec<u8>> = select
                .query_row(params![key.as_slice()], |row| row.get(0))
                .optional()?;
            if let Some(vector_blob) = vector_blob {
                update.execute(params![key.as_slice(), now])?;
                out.insert(*key, blob_to_vector(&vector_blob));
            }
        }
        drop(select);
        drop(update);
        tx.commit()?;
        Ok(out)
    }

    pub fn upsert_component_vectors(&self, items: &[([u8; 32], Vec<f32>)]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let now = now_unix_seconds();
        let mut stmt = tx.prepare(
            "INSERT INTO component_vectors(key, dim, vector, last_used_at)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO NOTHING",
        )?;
        for (key, vector) in items {
            stmt.execute(params![
                key.as_slice(),
                vector.len() as i64,
                vector_to_blob(vector),
                now
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_composed_vectors(&self, items: &[([u8; 32], Vec<f32>)]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare(
            "INSERT INTO vectors(key, dim, vector)
             VALUES(?1, ?2, ?3)
             ON CONFLICT(key) DO NOTHING",
        )?;
        for (key, vector) in items {
            stmt.execute(params![
                key.as_slice(),
                vector.len() as i64,
                vector_to_blob(vector)
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    pub fn replace_file_chunks(
        &self,
        workspace_id: i64,
        file_path: &str,
        state: &FileState,
        rows: &[ChunkRowIn<'_>],
    ) -> Result<()> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO files(workspace_id, file_path, file_hash, mtime_ns, size)
             VALUES(?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(workspace_id, file_path) DO UPDATE SET
                 file_hash = excluded.file_hash,
                 mtime_ns = excluded.mtime_ns,
                 size = excluded.size",
            params![
                workspace_id,
                file_path,
                state.file_hash.as_slice(),
                state.mtime_ns,
                state.size
            ],
        )?;
        tx.execute(
            "DELETE FROM chunks WHERE workspace_id = ?1 AND file_path = ?2",
            params![workspace_id, file_path],
        )?;

        let mut insert_doc = tx.prepare(
            "INSERT INTO bm25_docs(text_hash) VALUES(?1)
             ON CONFLICT(text_hash) DO NOTHING",
        )?;
        let mut select_doc = tx.prepare("SELECT doc_id FROM bm25_docs WHERE text_hash = ?1")?;
        let mut insert_fts = tx.prepare("INSERT INTO bm25_idx(rowid, tokens) VALUES(?1, ?2)")?;
        let mut insert_chunk = tx.prepare(
            "INSERT INTO chunks(
                 workspace_id, file_path, chunk_ord, kind, symbol,
                 start_line, end_line, composed_key, bm25_doc_id
             )
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        for row in rows {
            let inserted = insert_doc.execute(params![row.text_hash.as_slice()])? > 0;
            let doc_id: i64 =
                select_doc.query_row(params![row.text_hash.as_slice()], |db_row| db_row.get(0))?;
            if inserted {
                insert_fts.execute(params![doc_id, row.fts_tokens])?;
            }
            insert_chunk.execute(params![
                workspace_id,
                file_path,
                row.chunk_ord,
                row.kind,
                row.symbol,
                row.start_line,
                row.end_line,
                row.composed_key.as_slice(),
                doc_id
            ])?;
        }
        drop(insert_doc);
        drop(select_doc);
        drop(insert_fts);
        drop(insert_chunk);
        tx.commit()?;
        Ok(())
    }

    pub fn scan_vectors(
        &self,
        workspace_id: i64,
        batch_size: usize,
        visit: &mut dyn FnMut(Vec<ScanRow>),
    ) -> Result<()> {
        let effective_batch = batch_size.max(1);
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT c.file_path, c.kind, c.chunk_ord, v.vector
             FROM chunks c
             JOIN vectors v ON v.key = c.composed_key
             WHERE c.workspace_id = ?1
             ORDER BY c.file_path, c.chunk_ord",
        )?;
        let mut rows = stmt.query([workspace_id])?;
        let mut batch = Vec::with_capacity(effective_batch);
        while let Some(row) = rows.next()? {
            let kind: String = row.get(1)?;
            let vector_blob: Vec<u8> = row.get(3)?;
            batch.push(ScanRow {
                file_path: row.get(0)?,
                kind_is_summary: kind == "file_summary",
                chunk_ord: row.get(2)?,
                vector: blob_to_vector(&vector_blob),
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

    pub fn bm25_file_scores(
        &self,
        workspace_id: i64,
        match_query: &str,
        limit: usize,
    ) -> Result<Vec<(String, f64)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut fts_stmt = conn.prepare(
            "SELECT rowid, bm25(bm25_idx)
             FROM bm25_idx
             WHERE bm25_idx MATCH ?1",
        )?;
        let mut fts_rows = fts_stmt.query([match_query])?;
        let mut doc_scores = HashMap::<i64, f64>::new();
        while let Some(row) = fts_rows.next()? {
            let doc_id: i64 = row.get(0)?;
            let score: f64 = -row.get::<_, f64>(1)?;
            doc_scores.insert(doc_id, score);
        }
        drop(fts_rows);
        drop(fts_stmt);
        if doc_scores.is_empty() {
            return Ok(Vec::new());
        }

        let mut file_scores = HashMap::<String, f64>::new();
        let doc_ids: Vec<i64> = doc_scores.keys().copied().collect();
        for chunk in doc_ids.chunks(SQLITE_IN_LIMIT) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT file_path, bm25_doc_id
                 FROM chunks
                 WHERE workspace_id = ? AND bm25_doc_id IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql)?;
            let params_iter = std::iter::once(rusqlite::types::Value::Integer(workspace_id))
                .chain(chunk.iter().copied().map(rusqlite::types::Value::Integer));
            let mut rows = stmt.query(rusqlite::params_from_iter(params_iter))?;
            while let Some(row) = rows.next()? {
                let file_path: String = row.get(0)?;
                let doc_id: i64 = row.get(1)?;
                if let Some(score) = doc_scores.get(&doc_id) {
                    file_scores
                        .entry(file_path)
                        .and_modify(|best| {
                            if *score > *best {
                                *best = *score;
                            }
                        })
                        .or_insert(*score);
                }
            }
        }

        let mut scored_files: Vec<(String, f64)> = file_scores.into_iter().collect();
        scored_files.sort_by(|(path_a, score_a), (path_b, score_b)| {
            score_b
                .partial_cmp(score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| path_a.cmp(path_b))
        });
        scored_files.truncate(limit);
        Ok(scored_files)
    }

    pub fn gc(&self, component_ttl_secs: i64) -> Result<()> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;

        tx.execute(
            "DELETE FROM vectors
             WHERE NOT EXISTS (
                 SELECT 1 FROM chunks WHERE chunks.composed_key = vectors.key
             )",
            [],
        )?;

        let mut orphan_stmt = tx.prepare(
            "SELECT doc_id FROM bm25_docs
             WHERE NOT EXISTS (
                 SELECT 1 FROM chunks WHERE chunks.bm25_doc_id = bm25_docs.doc_id
             )",
        )?;
        let mut orphan_rows = orphan_stmt.query([])?;
        let mut orphan_doc_ids = Vec::new();
        while let Some(row) = orphan_rows.next()? {
            orphan_doc_ids.push(row.get::<_, i64>(0)?);
        }
        drop(orphan_rows);
        drop(orphan_stmt);
        let mut delete_fts = tx.prepare("DELETE FROM bm25_idx WHERE rowid = ?1")?;
        let mut delete_doc = tx.prepare("DELETE FROM bm25_docs WHERE doc_id = ?1")?;
        for doc_id in orphan_doc_ids {
            delete_fts.execute([doc_id])?;
            delete_doc.execute([doc_id])?;
        }
        drop(delete_fts);
        drop(delete_doc);

        let cutoff = now_unix_seconds() - component_ttl_secs;
        tx.execute(
            "DELETE FROM component_vectors WHERE last_used_at < ?1",
            [cutoff],
        )?;

        tx.commit()?;
        conn.pragma_update(None, "incremental_vacuum", 0)?;
        Ok(())
    }

    fn missing_keys(&self, table: &str, keys: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let sql = format!("SELECT 1 FROM {table} WHERE key = ?1 LIMIT 1");
        let mut stmt = conn.prepare(&sql)?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for key in keys {
            if !seen.insert(*key) {
                continue;
            }
            let exists = stmt
                .query_row(params![key.as_slice()], |_row| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                out.push(*key);
            }
        }
        Ok(out)
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    assert_sqlite_version(conn)?;
    let current = schema_version(conn)?;
    if current > LATEST_SCHEMA_VERSION {
        return Err(StoreError::new(format!(
            "semantic store schema version {current} is newer than supported version {LATEST_SCHEMA_VERSION}"
        )));
    }

    for version in (current + 1)..=LATEST_SCHEMA_VERSION {
        let tx = conn.transaction()?;
        apply_migration(&tx, version)?;
        set_meta_value_tx(&tx, META_SCHEMA_VERSION, &version.to_string())?;
        tx.commit()?;
    }
    Ok(())
}

fn apply_migration(tx: &rusqlite::Transaction<'_>, version: i64) -> Result<()> {
    match version {
        1 => {
            tx.execute_batch(
                r#"
                CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE workspaces(
                  workspace_id INTEGER PRIMARY KEY,
                  root_path TEXT NOT NULL UNIQUE,
                  last_built_at INTEGER
                );
                CREATE TABLE files(
                  workspace_id INTEGER NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
                  file_path TEXT NOT NULL,
                  file_hash BLOB NOT NULL,
                  mtime_ns INTEGER NOT NULL,
                  size INTEGER NOT NULL,
                  PRIMARY KEY(workspace_id, file_path)
                );
                CREATE TABLE chunks(
                  workspace_id INTEGER NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
                  file_path TEXT NOT NULL,
                  chunk_ord INTEGER NOT NULL,
                  kind TEXT NOT NULL,
                  symbol TEXT,
                  start_line INTEGER,
                  end_line INTEGER,
                  composed_key BLOB NOT NULL,
                  bm25_doc_id INTEGER,
                  PRIMARY KEY(workspace_id, file_path, chunk_ord)
                );
                CREATE INDEX chunks_by_workspace_key ON chunks(workspace_id, composed_key);
                CREATE INDEX chunks_by_doc ON chunks(bm25_doc_id);
                CREATE TABLE vectors(
                  key BLOB PRIMARY KEY,
                  dim INTEGER NOT NULL,
                  vector BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE component_vectors(
                  key BLOB PRIMARY KEY,
                  dim INTEGER NOT NULL,
                  vector BLOB NOT NULL,
                  last_used_at INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE bm25_docs(
                  doc_id INTEGER PRIMARY KEY,
                  text_hash BLOB NOT NULL UNIQUE
                );
                CREATE VIRTUAL TABLE bm25_idx USING fts5(
                  tokens,
                  content='',
                  contentless_delete=1
                );
                "#,
            )?;
            Ok(())
        }
        other => Err(StoreError::new(format!(
            "no semantic store migration registered for schema version {other}"
        ))),
    }
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
    use crate::nlp::keys::content_hash;
    use tempfile::TempDir;

    #[test]
    fn semantic_db_path_uses_workspace_for_plain_dir() {
        let temp = TempDir::new().unwrap();
        assert_eq!(
            semantic_db_path(temp.path()),
            temp.path().join(".brokk/semantic_index.db")
        );
    }

    #[test]
    fn semantic_db_path_uses_repo_root_for_git_repo() {
        let temp = TempDir::new().unwrap();
        Repository::init(temp.path()).unwrap();
        let nested = temp.path().join("nested").join("deeper");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            semantic_db_path(&nested),
            temp.path().join(".brokk/semantic_index.db")
        );
    }

    #[test]
    fn semantic_db_path_uses_primary_root_for_linked_worktree() {
        let temp = TempDir::new().unwrap();
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

        assert_eq!(
            semantic_db_path(&worktree_root),
            repo_root.join(".brokk/semantic_index.db")
        );
    }

    #[test]
    fn fingerprint_and_text_version_resets_preserve_expected_tables() {
        let temp = TempDir::new().unwrap();
        let store = SemanticStore::open(&temp.path().join("semantic.db")).unwrap();
        let workspace_id = store.workspace_id("/workspace-a").unwrap();
        let state = sample_file_state(b"file-a");
        let row = sample_chunk(0, "alpha beta", [7; 32]);

        store
            .upsert_component_vectors(&[([1; 32], vec![0.25, 0.75])])
            .unwrap();
        store
            .upsert_composed_vectors(&[(row.composed_key, vec![1.0, 0.0])])
            .unwrap();
        store
            .replace_file_chunks(workspace_id, "src/lib.rs", &state, &[row])
            .unwrap();

        assert!(!store.ensure_embed_fingerprint("embed-v1").unwrap());
        assert!(!store.ensure_text_versions("bm25-v1", "chunker-v1").unwrap());

        store
            .replace_file_chunks(workspace_id, "src/lib.rs", &state, &[row])
            .unwrap();
        store
            .upsert_component_vectors(&[([1; 32], vec![0.25, 0.75])])
            .unwrap();
        store
            .upsert_composed_vectors(&[(row.composed_key, vec![1.0, 0.0])])
            .unwrap();

        assert!(store.ensure_embed_fingerprint("embed-v2").unwrap());
        assert_eq!(count_rows(&store, "vectors"), 0);
        assert_eq!(count_rows(&store, "component_vectors"), 0);
        assert_eq!(count_rows(&store, "chunks"), 0);
        assert_eq!(count_rows(&store, "files"), 0);
        assert_eq!(count_rows(&store, "bm25_docs"), 1);
        assert_eq!(count_rows(&store, "bm25_idx"), 1);

        store
            .upsert_composed_vectors(&[(row.composed_key, vec![1.0, 0.0])])
            .unwrap();
        store
            .replace_file_chunks(workspace_id, "src/lib.rs", &state, &[row])
            .unwrap();

        assert!(store.ensure_text_versions("bm25-v2", "chunker-v1").unwrap());
        assert_eq!(count_rows(&store, "chunks"), 0);
        assert_eq!(count_rows(&store, "files"), 0);
        assert_eq!(count_rows(&store, "bm25_docs"), 0);
        assert_eq!(count_rows(&store, "bm25_idx"), 0);
        assert_eq!(count_rows(&store, "vectors"), 1);
    }

    #[test]
    fn replace_file_chunks_is_idempotent_and_shares_docs_and_vectors() {
        let temp = TempDir::new().unwrap();
        let store = SemanticStore::open(&temp.path().join("semantic.db")).unwrap();
        let workspace_a = store.workspace_id("/workspace-a").unwrap();
        let workspace_b = store.workspace_id("/workspace-b").unwrap();
        let state = sample_file_state(b"same file");
        let row = sample_chunk(0, "shared token", [9; 32]);

        store
            .upsert_composed_vectors(&[(row.composed_key, vec![0.5, 0.5])])
            .unwrap();

        store
            .replace_file_chunks(workspace_a, "src/lib.rs", &state, &[row])
            .unwrap();
        store
            .replace_file_chunks(workspace_a, "src/lib.rs", &state, &[row])
            .unwrap();
        assert_eq!(count_rows(&store, "files"), 1);
        assert_eq!(count_rows(&store, "chunks"), 1);
        assert_eq!(count_rows(&store, "bm25_docs"), 1);
        assert_eq!(count_rows(&store, "vectors"), 1);

        store
            .replace_file_chunks(workspace_b, "src/lib.rs", &state, &[row])
            .unwrap();
        assert_eq!(count_rows(&store, "files"), 2);
        assert_eq!(count_rows(&store, "chunks"), 2);
        assert_eq!(count_rows(&store, "bm25_docs"), 1);
        assert_eq!(count_rows(&store, "vectors"), 1);
    }

    #[test]
    fn scan_vectors_and_bm25_scores_work_in_batches() {
        let temp = TempDir::new().unwrap();
        let store = SemanticStore::open(&temp.path().join("semantic.db")).unwrap();
        let workspace_id = store.workspace_id("/workspace-a").unwrap();

        let summary_key = [3; 32];
        let fn1_key = [4; 32];
        let fn2_key = [5; 32];
        store
            .upsert_composed_vectors(&[
                (summary_key, vec![1.0, 0.0]),
                (fn1_key, vec![0.0, 1.0]),
                (fn2_key, vec![0.5, 0.5]),
            ])
            .unwrap();

        store
            .replace_file_chunks(
                workspace_id,
                "a.rs",
                &sample_file_state(b"a"),
                &[
                    ChunkRowIn {
                        chunk_ord: 0,
                        kind: "file_summary",
                        symbol: None,
                        start_line: None,
                        end_line: None,
                        composed_key: summary_key,
                        text_hash: [13; 32],
                        fts_tokens: "rarealpha",
                    },
                    ChunkRowIn {
                        chunk_ord: 1,
                        kind: "function",
                        symbol: Some("alpha_fn"),
                        start_line: Some(1),
                        end_line: Some(4),
                        composed_key: fn1_key,
                        text_hash: [14; 32],
                        fts_tokens: "rarealpha common",
                    },
                ],
            )
            .unwrap();
        store
            .replace_file_chunks(
                workspace_id,
                "b.rs",
                &sample_file_state(b"b"),
                &[ChunkRowIn {
                    chunk_ord: 0,
                    kind: "function",
                    symbol: Some("beta_fn"),
                    start_line: Some(1),
                    end_line: Some(4),
                    composed_key: fn2_key,
                    text_hash: [15; 32],
                    fts_tokens: "common",
                }],
            )
            .unwrap();

        let mut batches = Vec::new();
        store
            .scan_vectors(workspace_id, 2, &mut |rows| batches.push(rows))
            .unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 1);
        assert!(batches[0][0].kind_is_summary);
        assert_eq!(batches[0][0].vector, vec![1.0, 0.0]);

        let scores = store
            .bm25_file_scores(workspace_id, "rarealpha", 1)
            .unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].0, "a.rs");
    }

    #[test]
    fn gc_removes_orphans_and_keeps_referenced_rows() {
        let temp = TempDir::new().unwrap();
        let store = SemanticStore::open(&temp.path().join("semantic.db")).unwrap();
        let workspace_id = store.workspace_id("/workspace-a").unwrap();
        let row = sample_chunk(0, "kepttoken", [21; 32]);

        store
            .upsert_component_vectors(&[([31; 32], vec![1.0, 0.0]), ([32; 32], vec![0.0, 1.0])])
            .unwrap();
        set_component_last_used_at(&store, [31; 32], now_unix_seconds());
        set_component_last_used_at(&store, [32; 32], now_unix_seconds() - 10_000);

        store
            .upsert_composed_vectors(&[
                (row.composed_key, vec![0.2, 0.8]),
                ([22; 32], vec![0.9, 0.1]),
            ])
            .unwrap();
        store
            .replace_file_chunks(workspace_id, "src/lib.rs", &sample_file_state(b"c"), &[row])
            .unwrap();

        store
            .remove_files(workspace_id, &[String::from("src/lib.rs")])
            .unwrap();
        assert_eq!(count_rows(&store, "chunks"), 0);
        assert_eq!(count_rows(&store, "files"), 0);
        assert_eq!(count_rows(&store, "bm25_docs"), 1);
        assert_eq!(count_rows(&store, "bm25_idx"), 1);
        assert_eq!(count_rows(&store, "vectors"), 2);

        store.gc(60).unwrap();

        assert_eq!(count_rows(&store, "bm25_docs"), 0);
        assert_eq!(count_rows(&store, "bm25_idx"), 0);
        assert_eq!(count_rows(&store, "vectors"), 0);
        assert_eq!(count_rows(&store, "component_vectors"), 1);
    }

    fn sample_file_state(bytes: &[u8]) -> FileState {
        FileState {
            file_hash: content_hash(bytes),
            mtime_ns: 123,
            size: bytes.len() as i64,
        }
    }

    fn sample_chunk<'a>(
        chunk_ord: i64,
        fts_tokens: &'a str,
        composed_key: [u8; 32],
    ) -> ChunkRowIn<'a> {
        ChunkRowIn {
            chunk_ord,
            kind: "function",
            symbol: Some("symbol"),
            start_line: Some(1),
            end_line: Some(2),
            composed_key,
            text_hash: content_hash(fts_tokens.as_bytes()),
            fts_tokens,
        }
    }

    fn count_rows(store: &SemanticStore, table: &str) -> i64 {
        let conn = store.conn.lock().expect("semantic store mutex poisoned");
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn set_component_last_used_at(store: &SemanticStore, key: [u8; 32], last_used_at: i64) {
        let conn = store.conn.lock().expect("semantic store mutex poisoned");
        conn.execute(
            "UPDATE component_vectors SET last_used_at = ?2 WHERE key = ?1",
            params![key.as_slice(), last_used_at],
        )
        .unwrap();
    }

    fn run_git<I, S>(cwd: &Path, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
