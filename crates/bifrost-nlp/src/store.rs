use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SQLITE_IN_LIMIT: usize = 500;

/// Resolve the cache shared by every worktree of a primary repository.
pub fn semantic_db_path(workspace_root: &Path) -> PathBuf {
    brokk_bifrost_analysis::gitblob::cache_db_path(workspace_root)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(String);

impl StoreError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::new(format!("semantic store I/O error: {error}"))
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new(format!("semantic store SQLite error: {error}"))
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct SemanticStore {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

/// Persisted metadata for one function. Source and embedding documents are not
/// stored; only raw-source BM25 tokens and the direct vector key survive.
#[derive(Debug, Clone)]
pub struct FileChunkIn<'a> {
    pub chunk_ord: i64,
    pub symbol: &'a str,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub fts_tokens: &'a str,
    pub vector_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileChunkRow {
    pub blob_oid: String,
    pub rel_path: String,
    pub chunk_ord: i64,
    pub symbol: String,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub fts_tokens: String,
    pub vector_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct VectorRow {
    pub vector_hash: [u8; 32],
    pub code: Vec<u8>,
}

impl SemanticStore {
    pub fn open(db_path: &Path) -> Result<Self> {
        let conn = brokk_bifrost_analysis::cache_db::open_unified_connection(db_path)
            .map_err(StoreError::new)?;
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS active_vectors(
                 vector_hash BLOB PRIMARY KEY
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

    /// Wipe only rebuildable semantic data when its model or text contracts change.
    pub fn ensure_index_compatible(
        &self,
        fingerprint: &str,
        chunker_version: &str,
        bm25_tokenizer_version: &str,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let read_contracts = |conn: &Connection| {
            conn.query_row(
                "SELECT embed_fingerprint, chunker_version, bm25_tokenizer_version
                 FROM cache_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
        };
        let (stored_fp, stored_chunker, stored_bm25): (
            Option<String>,
            Option<String>,
            Option<String>,
        ) = read_contracts(&conn)?;
        let matches = stored_fp.as_deref() == Some(fingerprint)
            && stored_chunker.as_deref() == Some(chunker_version)
            && stored_bm25.as_deref() == Some(bm25_tokenizer_version);
        if matches {
            return Ok(false);
        }

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (stored_fp, stored_chunker, stored_bm25): (
            Option<String>,
            Option<String>,
            Option<String>,
        ) = read_contracts(&tx)?;
        let first_run = stored_fp.is_none() && stored_chunker.is_none() && stored_bm25.is_none();
        let matches = stored_fp.as_deref() == Some(fingerprint)
            && stored_chunker.as_deref() == Some(chunker_version)
            && stored_bm25.as_deref() == Some(bm25_tokenizer_version);
        let wiped = if first_run || matches {
            false
        } else {
            tx.execute("DELETE FROM semantic_files", [])?;
            tx.execute("DELETE FROM semantic_vectors", [])?;
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

    /// Return path/OID pairs that have not been materialized. Existing rows are
    /// fetched in OID batches rather than by one point query per source file.
    pub fn missing_files(&self, files: &[(String, String)]) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut oid_seen = HashSet::new();
        let oids: Vec<&String> = files
            .iter()
            .map(|(oid, _)| oid)
            .filter(|oid| oid_seen.insert((*oid).clone()))
            .collect();
        let mut existing = HashSet::new();
        for batch in oids.chunks(SQLITE_IN_LIMIT) {
            let placeholders = std::iter::repeat_n("?", batch.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT blob_oid, rel_path FROM semantic_files
                 WHERE blob_oid IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql)?;
            let values = batch
                .iter()
                .map(|oid| rusqlite::types::Value::Text((*oid).clone()));
            let rows = stmt.query_map(rusqlite::params_from_iter(values), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                existing.insert(row?);
            }
        }

        let mut seen = HashSet::new();
        Ok(files
            .iter()
            .filter(|pair| seen.insert((*pair).clone()) && !existing.contains(*pair))
            .cloned()
            .collect())
    }

    pub fn missing_vector_hashes(&self, hashes: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT 1 FROM semantic_vectors WHERE vector_hash = ?1 LIMIT 1")?;
        let mut missing = Vec::new();
        let mut seen = HashSet::new();
        for hash in hashes {
            if seen.insert(*hash)
                && stmt
                    .query_row(params![hash.as_slice()], |_| Ok(()))
                    .optional()?
                    .is_none()
            {
                missing.push(*hash);
            }
        }
        Ok(missing)
    }

    pub fn upsert_vectors(&self, items: &[([u8; 32], Vec<f32>)]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare(
            "INSERT INTO semantic_vectors(vector_hash, dim, vector) VALUES(?1, ?2, ?3)
             ON CONFLICT(vector_hash) DO NOTHING",
        )?;
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

    /// Replace several path/OID materializations in one transaction.
    pub fn put_files(
        &self,
        files: &[(&str, &str, Option<&str>, &[FileChunkIn<'_>])],
    ) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut upsert_file = tx.prepare(
                "INSERT INTO semantic_files(blob_oid, rel_path, language) VALUES(?1, ?2, ?3)
                 ON CONFLICT(blob_oid, rel_path) DO UPDATE SET
                     language = excluded.language,
                     materialized_at = datetime('now')",
            )?;
            let mut delete_chunks = tx.prepare(
                "DELETE FROM semantic_file_chunks WHERE blob_oid = ?1 AND rel_path = ?2",
            )?;
            let mut insert_chunk = tx.prepare(
                "INSERT INTO semantic_file_chunks(
                     blob_oid, rel_path, chunk_ord, symbol, start_line, end_line,
                     fts_tokens, vector_hash
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for (oid, rel_path, language, chunks) in files {
                upsert_file.execute(params![oid, rel_path, language])?;
                delete_chunks.execute(params![oid, rel_path])?;
                for chunk in *chunks {
                    insert_chunk.execute(params![
                        oid,
                        rel_path,
                        chunk.chunk_ord,
                        chunk.symbol,
                        chunk.start_line,
                        chunk.end_line,
                        chunk.fts_tokens,
                        chunk.vector_hash.as_slice(),
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Load every cached path variant for the requested OIDs. The active-index
    /// caller selects only exact `(OID, path)` pairs in its worktree.
    pub fn chunks_for_oids(&self, oids: &[String]) -> Result<Vec<FileChunkRow>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut output = Vec::new();
        let mut seen = HashSet::new();
        let unique: Vec<&String> = oids.iter().filter(|oid| seen.insert(*oid)).collect();
        for batch in unique.chunks(SQLITE_IN_LIMIT) {
            let placeholders = std::iter::repeat_n("?", batch.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT blob_oid, rel_path, chunk_ord, symbol, start_line, end_line,
                        fts_tokens, vector_hash
                 FROM semantic_file_chunks
                 WHERE blob_oid IN ({placeholders})
                 ORDER BY blob_oid, rel_path, chunk_ord"
            );
            let mut stmt = conn.prepare(&sql)?;
            let values = batch
                .iter()
                .map(|oid| rusqlite::types::Value::Text((*oid).clone()));
            let mut rows = stmt.query(rusqlite::params_from_iter(values))?;
            while let Some(row) = rows.next()? {
                output.push(FileChunkRow {
                    blob_oid: row.get(0)?,
                    rel_path: row.get(1)?,
                    chunk_ord: row.get(2)?,
                    symbol: row.get(3)?,
                    start_line: row.get(4)?,
                    end_line: row.get(5)?,
                    fts_tokens: row.get(6)?,
                    vector_hash: decode_key_blob(row.get::<_, Vec<u8>>(7)?)?,
                });
            }
        }
        Ok(output)
    }

    pub fn set_active_vector_hashes(&self, hashes: &HashSet<[u8; 32]>) -> Result<()> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM active_vectors", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO active_vectors(vector_hash) VALUES(?1)
                 ON CONFLICT(vector_hash) DO NOTHING",
            )?;
            for hash in hashes {
                stmt.execute(params![hash.as_slice()])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn add_active_vectors(&self, hashes: &[[u8; 32]]) -> Result<()> {
        self.change_active_vectors(hashes, true)
    }

    pub fn remove_active_vectors(&self, hashes: &[[u8; 32]]) -> Result<()> {
        self.change_active_vectors(hashes, false)
    }

    fn change_active_vectors(&self, hashes: &[[u8; 32]], add: bool) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let sql = if add {
            "INSERT INTO active_vectors(vector_hash) VALUES(?1)
             ON CONFLICT(vector_hash) DO NOTHING"
        } else {
            "DELETE FROM active_vectors WHERE vector_hash = ?1"
        };
        {
            let mut stmt = tx.prepare(sql)?;
            for hash in hashes {
                stmt.execute(params![hash.as_slice()])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn scan_active_vectors(
        &self,
        batch_size: usize,
        visit: &mut dyn FnMut(Vec<VectorRow>),
    ) -> Result<()> {
        let effective_batch = batch_size.max(1);
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT vectors.vector_hash, vectors.vector
             FROM semantic_vectors AS vectors
             JOIN active_vectors AS active USING(vector_hash)",
        )?;
        let mut rows = stmt.query([])?;
        let mut batch = Vec::with_capacity(effective_batch);
        while let Some(row) = rows.next()? {
            batch.push(VectorRow {
                vector_hash: decode_key_blob(row.get::<_, Vec<u8>>(0)?)?,
                code: row.get(1)?,
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

    pub fn gc(&self, live: &HashSet<String>) -> Result<()> {
        self.gc_with(|oid| live.contains(oid)).map(|_| ())
    }

    /// Delete all path variants for unreachable OIDs and then orphan vectors.
    pub fn gc_with(&self, keep: impl Fn(&str) -> bool) -> Result<usize> {
        let mut conn = self.conn.lock().expect("semantic store mutex poisoned");
        let tx = conn.transaction()?;
        let dead: Vec<String> = {
            let mut stmt = tx.prepare("SELECT DISTINCT blob_oid FROM semantic_files")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter(|oid| !keep(oid))
                .collect()
        };
        {
            let mut delete = tx.prepare("DELETE FROM semantic_files WHERE blob_oid = ?1")?;
            for oid in &dead {
                delete.execute([oid])?;
            }
        }
        tx.execute(
            "DELETE FROM semantic_vectors
             WHERE vector_hash NOT IN (SELECT vector_hash FROM semantic_file_chunks)",
            [],
        )?;
        tx.commit()?;
        conn.pragma_update(None, "incremental_vacuum", 0)?;
        Ok(dead.len())
    }

    pub fn seconds_since_gc(&self) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("semantic store mutex poisoned");
        let stored: i64 = conn.query_row(
            "SELECT last_gc_at FROM cache_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(Some(stored)
            .filter(|value| *value > 0)
            .map(|value| brokk_bifrost_analysis::cache_db::now_unix_seconds() - value))
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
    use std::time::Duration;

    fn open_temp() -> (tempfile::TempDir, SemanticStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        (temp, store)
    }

    fn chunk(symbol: &'static str, vector_hash: [u8; 32]) -> FileChunkIn<'static> {
        FileChunkIn {
            chunk_ord: 0,
            symbol,
            start_line: Some(1),
            end_line: Some(2),
            fts_tokens: "raw source tokens",
            vector_hash,
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
    fn materializations_are_path_and_oid_specific() {
        let (_temp, store) = open_temp();
        let oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let left = [1; 32];
        let right = [2; 32];
        store
            .upsert_vectors(&[(left, vec![1.0]), (right, vec![2.0])])
            .unwrap();
        store
            .put_files(&[
                (oid, "src/a.rs", Some("rust"), &[chunk("a::run", left)]),
                (oid, "src/b.rs", Some("rust"), &[chunk("b::run", right)]),
            ])
            .unwrap();

        let rows = store.chunks_for_oids(&[oid.to_string()]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].rel_path, "src/a.rs");
        assert_eq!(rows[1].rel_path, "src/b.rs");
        assert_eq!(
            store
                .missing_files(&[
                    (oid.to_string(), "src/a.rs".to_string()),
                    (oid.to_string(), "src/c.rs".to_string()),
                ])
                .unwrap(),
            vec![(oid.to_string(), "src/c.rs".to_string())]
        );
    }

    #[test]
    fn active_vector_scan_is_connection_local_and_batched() {
        let (_temp, store) = open_temp();
        store
            .upsert_vectors(&[([1; 32], vec![1.0]), ([2; 32], vec![2.0])])
            .unwrap();
        store
            .set_active_vector_hashes(&HashSet::from([[2; 32]]))
            .unwrap();
        let mut seen = Vec::new();
        store
            .scan_active_vectors(1, &mut |rows| seen.extend(rows))
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].vector_hash, [2; 32]);
    }

    #[test]
    fn rejects_short_vector_hash() {
        let (_temp, store) = open_temp();
        let conn = store.conn.lock().unwrap();
        let error = conn
            .execute(
                "INSERT INTO semantic_vectors(vector_hash, dim, vector)
                 VALUES(?1, 3, X'010203')",
                [vec![1u8; 31]],
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("CHECK"),
            "expected CHECK constraint error, got {error}"
        );
    }

    #[test]
    fn gc_drops_all_dead_path_variants_and_orphan_vectors() {
        let (_temp, store) = open_temp();
        let keep = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let drop = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        store
            .upsert_vectors(&[([1; 32], vec![1.0]), ([2; 32], vec![2.0])])
            .unwrap();
        store
            .put_files(&[
                (keep, "a.rs", Some("rust"), &[chunk("a", [1; 32])]),
                (drop, "b.rs", Some("rust"), &[chunk("b", [2; 32])]),
                (drop, "c.rs", Some("rust"), &[chunk("c", [2; 32])]),
            ])
            .unwrap();

        assert_eq!(store.gc_with(|oid| oid == keep).unwrap(), 1);
        assert_eq!(store.chunks_for_oids(&[drop.to_string()]).unwrap(), vec![]);
        assert_eq!(
            store.missing_vector_hashes(&[[2; 32]]).unwrap(),
            vec![[2; 32]]
        );
    }

    #[test]
    fn compatibility_change_wipes_only_semantic_data() {
        let (_temp, store) = open_temp();
        assert!(!store.ensure_index_compatible("fp1", "ck1", "bm1").unwrap());
        let oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store.upsert_vectors(&[([1; 32], vec![1.0])]).unwrap();
        store
            .put_files(&[(oid, "a.rs", Some("rust"), &[chunk("a", [1; 32])])])
            .unwrap();

        assert!(store.ensure_index_compatible("fp2", "ck1", "bm1").unwrap());
        assert!(
            store
                .chunks_for_oids(&[oid.to_string()])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.missing_vector_hashes(&[[1; 32]]).unwrap(),
            vec![[1; 32]]
        );
    }

    #[test]
    fn matching_semantic_versions_do_not_wait_for_the_writer_slot() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("cache.db");
        let writer = SemanticStore::open(&database).unwrap();
        let reader = SemanticStore::open(&database).unwrap();
        writer.ensure_index_compatible("fp", "ck", "bm").unwrap();

        reader
            .conn
            .lock()
            .unwrap()
            .busy_timeout(Duration::from_millis(100))
            .unwrap();
        let mut writer_connection = writer.conn.lock().unwrap();
        let writer_transaction = writer_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();

        assert!(!reader.ensure_index_compatible("fp", "ck", "bm").unwrap());
        writer_transaction.rollback().unwrap();
    }

    #[test]
    fn semantic_db_path_uses_primary_root_for_linked_worktree() {
        let temp = tempfile::tempdir().unwrap();
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
            actual.file_name().and_then(|name| name.to_str()),
            Some(brokk_bifrost_analysis::cache_db::cache_db_file_name())
        );
        let actual_root = actual
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .unwrap();
        assert_eq!(
            std::fs::canonicalize(actual_root).unwrap(),
            std::fs::canonicalize(&repo_root).unwrap()
        );
    }
}
