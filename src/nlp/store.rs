use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SQLITE_IN_LIMIT: usize = 500;

/// Resolve the per-primary-repo cache path. Worktrees collapse to the primary
/// repo so every checkout of one repo shares a single content-addressed cache.
///
/// Callers must already have gated on git availability (semantic search is git
/// only); for a non-repo path this still returns a path, but the indexer is
/// never started there.
pub fn semantic_db_path(workspace_root: &Path) -> PathBuf {
    crate::gitblob::cache_db_path(workspace_root)
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
    db_path: PathBuf,
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
    /// `hash(text)` — key into `semantic_component_vectors`.
    pub hash: [u8; 32],
    /// `hash(parent_summary)` — key into `semantic_component_vectors` and `semantic_blob_summaries`.
    pub parent_summary_hash: Option<[u8; 32]>,
    /// `compose(...)` — key into `semantic_vectors` (the searchable vector).
    pub composed_hash: [u8; 32],
}

/// A chunk row read back for active-index construction. Carries `blob_oid` so the
/// caller can attach the per-worktree path; `text`/keys for embedding are not
/// needed here (the semantic_vectors already live in the cache, keyed by `composed_hash`).
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
        let conn = crate::cache_db::open_unified_connection(db_path).map_err(StoreError::new)?;
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS active_chunks(
                 composed_hash BLOB PRIMARY KEY
             ) WITHOUT ROWID, STRICT;",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            db_path: db_path.to_path_buf(),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
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
        let (stored_fp, stored_chunker, stored_bm25): (
            Option<String>,
            Option<String>,
            Option<String>,
        ) = tx.query_row(
            "SELECT embed_fingerprint, chunker_version, bm25_tokenizer_version
             FROM cache_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let first_run = stored_fp.is_none() && stored_chunker.is_none() && stored_bm25.is_none();
        let matches = stored_fp.as_deref() == Some(fingerprint)
            && stored_chunker.as_deref() == Some(chunker_version)
            && stored_bm25.as_deref() == Some(bm25_tokenizer_version);
        let wiped = if first_run || matches {
            false
        } else {
            // semantic_blob_chunks cascade from semantic_blobs.
            tx.execute("DELETE FROM semantic_blobs", [])?;
            tx.execute("DELETE FROM semantic_blob_summaries", [])?;
            tx.execute("DELETE FROM semantic_vectors", [])?;
            tx.execute("DELETE FROM semantic_component_vectors", [])?;
            true
        };
        tx.execute(
            "UPDATE cache_state
             SET embed_fingerprint = ?1,
                 chunker_version = ?2,
                 bm25_tokenizer_version = ?3
             WHERE id = 1",
            params![fingerprint, chunker_version, bm25_tokenizer_version],
        )?;
        tx.commit()?;
        Ok(wiped)
    }

    // ---- materialization (write path) ------------------------------------

    /// Which of `oids` are not yet materialized in the cache.
    pub fn missing_blobs(&self, oids: &[String]) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut stmt = conn.prepare("SELECT 1 FROM semantic_blobs WHERE blob_oid = ?1 LIMIT 1")?;
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
        self.missing_hashes("semantic_component_vectors", "hash", hashes)
    }

    pub fn missing_composed_hashes(&self, hashes: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        self.missing_hashes("semantic_vectors", "composed_hash", hashes)
    }

    /// Component semantic_vectors are stored as fastrq codes; decode them (lossily) back to
    /// f32 for re-composition.
    pub fn component_vectors(&self, hashes: &[[u8; 32]]) -> Result<HashMap<[u8; 32], Vec<f32>>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut select =
            conn.prepare("SELECT vector FROM semantic_component_vectors WHERE hash = ?1")?;
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
        self.upsert_codes("semantic_component_vectors", "hash", items)
    }

    pub fn upsert_composed_vectors(&self, items: &[([u8; 32], Vec<f32>)]) -> Result<()> {
        self.upsert_codes("semantic_vectors", "composed_hash", items)
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
            let code = super::metrics::time(&super::metrics::ENCODE_NS, || {
                super::quant::encode_vector(vector)
            });
            super::metrics::time(&super::metrics::SQLITE_NS, || {
                stmt.execute(params![key.as_slice(), vector.len() as i64, code])
            })?;
        }
        drop(stmt);
        super::metrics::time(&super::metrics::SQLITE_NS, || tx.commit())?;
        Ok(())
    }

    /// Replace several semantic_blobs' materialized chunks in a single transaction. With a
    /// group of 64 semantic_blobs this collapses ~64 transactions (and their fsyncs) into one,
    /// the dominant SQLite cost during materialization.
    pub fn put_blobs(
        &self,
        semantic_blobs: &[(&str, Option<&str>, &[BlobChunkIn<'_>])],
    ) -> Result<()> {
        if semantic_blobs.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut upsert_blob = tx.prepare(
                "INSERT INTO semantic_blobs(blob_oid, language) VALUES(?1, ?2)
                 ON CONFLICT(blob_oid) DO UPDATE SET
                     language = excluded.language,
                     materialized_at = datetime('now')",
            )?;
            let mut delete_chunks =
                tx.prepare("DELETE FROM semantic_blob_chunks WHERE blob_oid = ?1")?;
            let mut intern_summary = tx.prepare(
                "INSERT INTO semantic_blob_summaries(hash) VALUES(?1) ON CONFLICT(hash) DO NOTHING",
            )?;
            let mut select_summary =
                tx.prepare("SELECT blob_summary_id FROM semantic_blob_summaries WHERE hash = ?1")?;
            let mut insert_chunk = tx.prepare(
                "INSERT INTO semantic_blob_chunks(
                     blob_oid, chunk_ord, kind, symbol, start_line, end_line,
                     fts_tokens, hash, parent_summary_id, composed_hash
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            let mut summary_ids: HashMap<[u8; 32], i64> = HashMap::new();
            for (blob_oid, language, chunks) in semantic_blobs {
                upsert_blob.execute(params![blob_oid, language])?;
                delete_chunks.execute([blob_oid])?;
                for chunk in *chunks {
                    let parent_summary_id = match chunk.parent_summary_hash {
                        None => None,
                        Some(hash) => Some(match summary_ids.get(&hash) {
                            Some(id) => *id,
                            None => {
                                intern_summary.execute(params![hash.as_slice()])?;
                                let id: i64 = select_summary
                                    .query_row(params![hash.as_slice()], |row| row.get(0))?;
                                summary_ids.insert(hash, id);
                                id
                            }
                        }),
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
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Replace one blob's materialized chunks (and intern its parent summaries).
    /// The component/composed semantic_vectors must already be upserted.
    pub fn put_blob(
        &self,
        blob_oid: &str,
        language: Option<&str>,
        chunks: &[BlobChunkIn<'_>],
    ) -> Result<()> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO semantic_blobs(blob_oid, language) VALUES(?1, ?2)
             ON CONFLICT(blob_oid) DO UPDATE SET
                 language = excluded.language,
                 materialized_at = datetime('now')",
            params![blob_oid, language],
        )?;
        tx.execute(
            "DELETE FROM semantic_blob_chunks WHERE blob_oid = ?1",
            [blob_oid],
        )?;

        let mut intern_summary = tx.prepare(
            "INSERT INTO semantic_blob_summaries(hash) VALUES(?1) ON CONFLICT(hash) DO NOTHING",
        )?;
        let mut select_summary =
            tx.prepare("SELECT blob_summary_id FROM semantic_blob_summaries WHERE hash = ?1")?;
        let mut insert_chunk = tx.prepare(
            "INSERT INTO semantic_blob_chunks(
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
                 FROM semantic_blob_chunks
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

    /// Stream the active set's searchable semantic_vectors in batches. Producer side of
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
             FROM semantic_vectors v
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

    /// Drop everything no longer reachable from git (or held by a worktree's uncommitted
    /// working set). `live` is the union of reachable blob OIDs and currently-checked-out
    /// dirty/untracked OIDs. Convenience wrapper over [`gc_with`] for an exact set.
    pub fn gc(&self, live: &HashSet<String>) -> Result<()> {
        self.gc_with(|oid| live.contains(oid)).map(|_| ())
    }

    /// Drop every cached blob for which `keep(blob_oid)` is false, cascading to its chunks
    /// and any now-orphaned semantic_vectors/summaries. Returns the number of semantic_blobs dropped.
    ///
    /// Streams the semantic_blobs table past `keep` and materializes only the (usually small) dead
    /// set, so peak memory is O(dropped), not O(all cached semantic_blobs) — letting the caller pass
    /// a Bloom-filter membership test (`gitcache::reachable_bloom`) and never hold the OID
    /// set. `keep` must not return false for a live blob; a Bloom test satisfies this (no
    /// false negatives), at the cost of occasionally keeping a dead blob (false positive).
    pub fn gc_with(&self, keep: impl Fn(&str) -> bool) -> Result<usize> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let dead: Vec<String> = {
            let mut stmt = tx.prepare("SELECT blob_oid FROM semantic_blobs")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut dead = Vec::new();
            for oid in rows {
                let oid = oid?;
                if !keep(&oid) {
                    dead.push(oid);
                }
            }
            dead
        };
        {
            // semantic_blob_chunks cascade from semantic_blobs.
            let mut del = tx.prepare("DELETE FROM semantic_blobs WHERE blob_oid = ?1")?;
            for oid in &dead {
                del.execute([oid])?;
            }
        }
        tx.execute(
            "DELETE FROM semantic_vectors
             WHERE composed_hash NOT IN (SELECT composed_hash FROM semantic_blob_chunks)",
            [],
        )?;
        tx.execute(
            "DELETE FROM semantic_blob_summaries
             WHERE blob_summary_id NOT IN (
                 SELECT parent_summary_id FROM semantic_blob_chunks
                 WHERE parent_summary_id IS NOT NULL
             )",
            [],
        )?;
        tx.execute(
            "DELETE FROM semantic_component_vectors
             WHERE hash NOT IN (
                 SELECT hash FROM semantic_blob_chunks
                 UNION SELECT hash FROM semantic_blob_summaries
             )",
            [],
        )?;
        tx.commit()?;
        conn.pragma_update(None, "incremental_vacuum", 0)?;
        Ok(dead.len())
    }

    /// Seconds since the last `gc`, or `None` if never run.
    pub fn seconds_since_gc(&self) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let stored: i64 = conn.query_row(
            "SELECT last_gc_at FROM cache_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(Some(stored)
            .filter(|at| *at > 0)
            .map(|at| crate::cache_db::now_unix_seconds() - at))
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

fn decode_key_blob(blob: Vec<u8>) -> Result<[u8; 32]> {
    blob.try_into().map_err(|value: Vec<u8>| {
        StoreError::new(format!(
            "expected 32-byte key blob, got {} bytes",
            value.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn open_temp() -> (tempfile::TempDir, SemanticStore) {
        let temp = tempfile::TempDir::new().unwrap();
        let store =
            SemanticStore::open(&temp.path().join(crate::cache_db::CACHE_DB_FILE_NAME)).unwrap();
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
            .args(["-c", "commit.gpgSign=false"])
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
        let oid_a = "1111111111111111111111111111111111111111";
        let oid_b = "2222222222222222222222222222222222222222";
        store
            .put_blob(
                oid_a,
                Some("rust"),
                &[
                    chunk(0, [2; 32], [5; 32], None),
                    chunk(1, [1; 32], [6; 32], Some(parent)),
                ],
            )
            .unwrap();

        let rows = store.chunks_for_oids(&[oid_a.to_string()]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, "file_summary");
        assert_eq!(rows[1].symbol.as_deref(), Some("pkg.Cls.method"));
        assert_eq!(rows[1].composed_hash, [6; 32]);

        assert!(
            store.missing_blobs(&[oid_a.into(), oid_b.into()]).unwrap() == vec![oid_b.to_string()]
        );
    }

    #[test]
    fn scan_active_vectors_respects_active_set() {
        let (_temp, store) = open_temp();
        store
            .upsert_composed_vectors(&[([5; 32], vec![1.0, 0.0]), ([6; 32], vec![0.0, 1.0])])
            .unwrap();
        let oid_a = "1111111111111111111111111111111111111111";
        store
            .put_blob(oid_a, None, &[chunk(1, [1; 32], [5; 32], None)])
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
    fn rejects_short_semantic_hash_key() {
        let (_temp, store) = open_temp();
        let conn = store.conn.lock().unwrap();
        let err = conn
            .execute(
                "INSERT INTO semantic_component_vectors(hash, dim, vector)
                 VALUES(?1, 3, X'010203')",
                [vec![1u8; 31]],
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("CHECK"),
            "expected CHECK constraint error, got {err}"
        );
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
        let oid_keep = "1111111111111111111111111111111111111111";
        let oid_drop = "2222222222222222222222222222222222222222";
        store
            .put_blob(oid_keep, None, &[chunk(1, [1; 32], [5; 32], None)])
            .unwrap();
        store
            .put_blob(oid_drop, None, &[chunk(1, [1; 32], [5; 32], None)])
            .unwrap();

        let live: HashSet<String> = [oid_keep.to_string()].into_iter().collect();
        store.gc(&live).unwrap();

        assert_eq!(store.chunks_for_oids(&[oid_drop.into()]).unwrap().len(), 0);
        assert_eq!(store.chunks_for_oids(&[oid_keep.into()]).unwrap().len(), 1);
        // The shared vector/component are still referenced by oid_keep.
        assert!(
            store
                .missing_composed_hashes(&[[5; 32]])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn version_change_wipes_cache() {
        let (_temp, store) = open_temp();
        assert!(!store.ensure_index_compatible("fp1", "ck1", "bm1").unwrap());
        store
            .upsert_composed_vectors(&[([5; 32], vec![1.0, 0.0])])
            .unwrap();
        let oid_a = "1111111111111111111111111111111111111111";
        store
            .put_blob(oid_a, None, &[chunk(1, [1; 32], [5; 32], None)])
            .unwrap();

        assert!(store.ensure_index_compatible("fp2", "ck1", "bm1").unwrap());
        assert_eq!(store.chunks_for_oids(&[oid_a.into()]).unwrap().len(), 0);
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
            Some(crate::cache_db::CACHE_DB_FILE_NAME)
        );
        let actual_root = actual.parent().and_then(Path::parent).unwrap();
        assert_eq!(
            std::fs::canonicalize(actual_root).unwrap(),
            std::fs::canonicalize(&repo_root).unwrap()
        );
    }
}
