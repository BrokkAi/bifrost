//! Connection-local active semantic index.
//!
//! The persistent database stores reusable `(blob_oid, rel_path)` facts. This
//! module joins those facts to one worktree's exact `rel_path -> blob_oid` map.
//! SQLite holds active membership, exact-corpus FTS, and distinct vector keys
//! in TEMP tables. Rust keeps compact maps for hot vector-hit resolution.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rusqlite::{Connection, params};

use super::store::SemanticStore;

type Key = [u8; 32];

struct Occurrence {
    file_id: u32,
    fqfn: String,
    start_line: Option<i64>,
    end_line: Option<i64>,
    vector_hash: Key,
}

struct OccurrenceRow {
    occ_id: u32,
    path: String,
    symbol: String,
    start_line: Option<i64>,
    end_line: Option<i64>,
    vector_hash: Key,
}

pub struct VectorRow {
    pub vector_hash: Key,
    pub code: Vec<u8>,
}

/// A resolved function hit returned to the query layer.
pub struct FunctionHit<'a> {
    pub fqfn: &'a str,
    pub path: &'a str,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
}

pub struct ActiveIndex {
    paths: Vec<Arc<str>>,
    path_ids: HashMap<Arc<str>, u32>,
    /// `occ[occ_id]`; `None` is either rowid zero or a watcher tombstone.
    occ: Vec<Option<Occurrence>>,
    by_vector: HashMap<Key, Vec<u32>>,
    by_file: HashMap<u32, Vec<u32>>,
    active_hashes: HashSet<Key>,
    session: Mutex<Connection>,
}

impl ActiveIndex {
    /// Build the active index for one worktree. All referenced files must be
    /// materialized before this function starts.
    pub fn build(
        store: &SemanticStore,
        path_to_oid: &HashMap<String, String>,
    ) -> Result<Self, String> {
        let total_started = Instant::now();
        let mut conn =
            brokk_bifrost_analysis::cache_db::open_readonly_temp_connection(store.db_path())?;
        create_active_schema(&conn)?;
        let membership_started = Instant::now();
        {
            let tx = conn.transaction().map_err(|err| err.to_string())?;
            {
                let mut insert = tx
                    .prepare("INSERT INTO active_files(rel_path, blob_oid) VALUES(?1, ?2)")
                    .map_err(|err| err.to_string())?;
                for (path, oid) in path_to_oid {
                    insert
                        .execute(params![path, oid])
                        .map_err(|err| err.to_string())?;
                }
            }
            tx.execute_batch("ANALYZE temp.active_files;")
                .map_err(|err| err.to_string())?;
            let membership_elapsed = membership_started.elapsed();

            let occurrences_started = Instant::now();
            tx.execute_batch(
                "INSERT INTO active_occurrences(rel_path, chunk_ord)
                 SELECT active.rel_path, chunks.chunk_ord
                 FROM active_files AS active
                 JOIN semantic_file_chunks AS chunks
                   ON chunks.blob_oid = active.blob_oid
                  AND chunks.rel_path = active.rel_path
                 ORDER BY active.rel_path, chunks.chunk_ord;",
            )
            .map_err(|err| err.to_string())?;
            let occurrences_elapsed = occurrences_started.elapsed();

            let vectors_started = Instant::now();
            tx.execute_batch(
                "INSERT INTO active_vectors(vector_hash)
                 SELECT DISTINCT chunks.vector_hash
                 FROM active_occurrences AS occurrence
                 JOIN active_files AS active USING(rel_path)
                 JOIN semantic_file_chunks AS chunks
                   ON chunks.blob_oid = active.blob_oid
                  AND chunks.rel_path = active.rel_path
                  AND chunks.chunk_ord = occurrence.chunk_ord;
                 ANALYZE temp.active_vectors;",
            )
            .map_err(|err| err.to_string())?;
            let vectors_elapsed = vectors_started.elapsed();

            let fts_started = Instant::now();
            tx.execute_batch(
                "INSERT INTO bm25_idx(rowid, tokens)
                 SELECT occurrence.occ_id, chunks.fts_tokens
                 FROM active_occurrences AS occurrence
                 JOIN active_files AS active USING(rel_path)
                 JOIN semantic_file_chunks AS chunks
                   ON chunks.blob_oid = active.blob_oid
                  AND chunks.rel_path = active.rel_path
                  AND chunks.chunk_ord = occurrence.chunk_ord;",
            )
            .map_err(|err| err.to_string())?;
            let fts_elapsed = fts_started.elapsed();
            tx.commit().map_err(|err| err.to_string())?;

            eprintln!(
                "bifrost semantic active SQL: files={}; membership={membership_elapsed:?}; occurrences={occurrences_elapsed:?}; vectors={vectors_elapsed:?}; fts={fts_elapsed:?}",
                path_to_oid.len()
            );
        }

        let metadata_started = Instant::now();
        let rows = load_all_occurrence_rows(&conn)?;
        let mut index = ActiveIndex {
            paths: Vec::new(),
            path_ids: HashMap::new(),
            occ: vec![None],
            by_vector: HashMap::new(),
            by_file: HashMap::new(),
            active_hashes: HashSet::new(),
            session: Mutex::new(conn),
        };
        for row in rows {
            index.add_row(row);
        }
        eprintln!(
            "bifrost semantic active maps: occurrences={}; vectors={}; metadata={:?}; total={:?}",
            index.occurrence_count(),
            index.active_hashes.len(),
            metadata_started.elapsed(),
            total_started.elapsed()
        );
        Ok(index)
    }

    /// Apply watcher changes to the connection-local relation and Rust maps.
    pub fn apply_changes(
        &mut self,
        changed: &HashMap<String, String>,
        removed: &[String],
    ) -> Result<(), String> {
        let changed_paths: HashSet<String> = changed.keys().cloned().collect();
        let changed_rows = {
            let mut conn = self.session.lock().expect("active session mutex poisoned");
            let tx = conn.transaction().map_err(|err| err.to_string())?;
            tx.execute("DELETE FROM touched_vectors", [])
                .map_err(|err| err.to_string())?;

            for path in removed.iter().chain(changed.keys()) {
                tx.execute(
                    "INSERT INTO touched_vectors(vector_hash)
                     SELECT DISTINCT chunks.vector_hash
                     FROM active_occurrences AS occurrence
                     JOIN active_files AS active USING(rel_path)
                     JOIN semantic_file_chunks AS chunks
                       ON chunks.blob_oid = active.blob_oid
                      AND chunks.rel_path = active.rel_path
                      AND chunks.chunk_ord = occurrence.chunk_ord
                     WHERE occurrence.rel_path = ?1
                     ON CONFLICT(vector_hash) DO NOTHING",
                    [path],
                )
                .map_err(|err| err.to_string())?;
                tx.execute(
                    "DELETE FROM bm25_idx
                     WHERE rowid IN (
                         SELECT occ_id FROM active_occurrences WHERE rel_path = ?1
                     )",
                    [path],
                )
                .map_err(|err| err.to_string())?;
                tx.execute("DELETE FROM active_files WHERE rel_path = ?1", [path])
                    .map_err(|err| err.to_string())?;
            }

            for (path, oid) in changed {
                tx.execute(
                    "INSERT INTO active_files(rel_path, blob_oid) VALUES(?1, ?2)",
                    params![path, oid],
                )
                .map_err(|err| err.to_string())?;
                tx.execute(
                    "INSERT INTO active_occurrences(rel_path, chunk_ord)
                     SELECT active.rel_path, chunks.chunk_ord
                     FROM active_files AS active
                     JOIN semantic_file_chunks AS chunks
                       ON chunks.blob_oid = active.blob_oid
                      AND chunks.rel_path = active.rel_path
                     WHERE active.rel_path = ?1
                     ORDER BY chunks.chunk_ord",
                    [path],
                )
                .map_err(|err| err.to_string())?;
                tx.execute(
                    "INSERT INTO bm25_idx(rowid, tokens)
                     SELECT occurrence.occ_id, chunks.fts_tokens
                     FROM active_occurrences AS occurrence
                     JOIN active_files AS active USING(rel_path)
                     JOIN semantic_file_chunks AS chunks
                       ON chunks.blob_oid = active.blob_oid
                      AND chunks.rel_path = active.rel_path
                      AND chunks.chunk_ord = occurrence.chunk_ord
                     WHERE occurrence.rel_path = ?1",
                    [path],
                )
                .map_err(|err| err.to_string())?;
                tx.execute(
                    "INSERT INTO touched_vectors(vector_hash)
                     SELECT DISTINCT chunks.vector_hash
                     FROM active_occurrences AS occurrence
                     JOIN active_files AS active USING(rel_path)
                     JOIN semantic_file_chunks AS chunks
                       ON chunks.blob_oid = active.blob_oid
                      AND chunks.rel_path = active.rel_path
                      AND chunks.chunk_ord = occurrence.chunk_ord
                     WHERE occurrence.rel_path = ?1
                     ON CONFLICT(vector_hash) DO NOTHING",
                    [path],
                )
                .map_err(|err| err.to_string())?;
            }

            tx.execute(
                "DELETE FROM active_vectors
                 WHERE vector_hash IN (SELECT vector_hash FROM touched_vectors)",
                [],
            )
            .map_err(|err| err.to_string())?;
            tx.execute(
                "INSERT INTO active_vectors(vector_hash)
                 SELECT DISTINCT chunks.vector_hash
                 FROM active_occurrences AS occurrence
                 JOIN active_files AS active USING(rel_path)
                 JOIN semantic_file_chunks AS chunks
                   ON chunks.blob_oid = active.blob_oid
                  AND chunks.rel_path = active.rel_path
                  AND chunks.chunk_ord = occurrence.chunk_ord
                 JOIN touched_vectors AS touched
                   ON touched.vector_hash = chunks.vector_hash
                 ON CONFLICT(vector_hash) DO NOTHING",
                [],
            )
            .map_err(|err| err.to_string())?;

            let rows = load_occurrence_rows_for_paths(&tx, &changed_paths)?;
            tx.commit().map_err(|err| err.to_string())?;
            rows
        };

        let mut touched = HashSet::new();
        for path in removed.iter().chain(changed.keys()) {
            self.evict_path(path, &mut touched);
        }
        for row in changed_rows {
            touched.insert(row.vector_hash);
            self.add_row(row);
        }
        debug_assert_eq!(
            touched
                .iter()
                .filter(|hash| self.active_hashes.contains(*hash))
                .count(),
            touched
                .iter()
                .filter(|hash| self.by_vector.contains_key(*hash))
                .count()
        );
        Ok(())
    }

    fn evict_path(&mut self, path: &str, touched: &mut HashSet<Key>) {
        let Some(&file_id) = self.path_ids.get(path) else {
            return;
        };
        let Some(occ_ids) = self.by_file.remove(&file_id) else {
            return;
        };
        for occ_id in occ_ids {
            let Some(occurrence) = self.occ[occ_id as usize].take() else {
                continue;
            };
            if let Some(bucket) = self.by_vector.get_mut(&occurrence.vector_hash) {
                bucket.retain(|id| *id != occ_id);
                if bucket.is_empty() {
                    self.by_vector.remove(&occurrence.vector_hash);
                    self.active_hashes.remove(&occurrence.vector_hash);
                }
            }
            touched.insert(occurrence.vector_hash);
        }
    }

    fn add_row(&mut self, row: OccurrenceRow) {
        let file_id = intern_path(&mut self.paths, &mut self.path_ids, &row.path);
        let index = row.occ_id as usize;
        if self.occ.len() <= index {
            self.occ.resize_with(index + 1, || None);
        }
        assert!(
            self.occ[index].is_none(),
            "active occurrence rowid {} was already occupied",
            row.occ_id
        );
        self.occ[index] = Some(Occurrence {
            file_id,
            fqfn: row.symbol,
            start_line: row.start_line,
            end_line: row.end_line,
            vector_hash: row.vector_hash,
        });
        self.by_vector
            .entry(row.vector_hash)
            .or_default()
            .push(row.occ_id);
        self.by_file.entry(file_id).or_default().push(row.occ_id);
        self.active_hashes.insert(row.vector_hash);
    }

    /// Function occurrences for one direct vector hash.
    pub fn resolve(&self, vector_hash: &Key) -> Vec<FunctionHit<'_>> {
        let Some(ids) = self.by_vector.get(vector_hash) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| {
                let occurrence = self.occ[*id as usize].as_ref()?;
                Some(FunctionHit {
                    fqfn: &occurrence.fqfn,
                    path: &self.paths[occurrence.file_id as usize],
                    start_line: occurrence.start_line,
                    end_line: occurrence.end_line,
                })
            })
            .collect()
    }

    /// Stream compressed active vectors without loading the corpus into memory.
    pub fn scan_vectors(
        &self,
        batch_size: usize,
        visit: &mut dyn FnMut(Vec<VectorRow>),
    ) -> Result<(), String> {
        let effective_batch = batch_size.max(1);
        let conn = self.session.lock().expect("active session mutex poisoned");
        let mut statement = conn
            .prepare(
                "SELECT vectors.vector_hash, vectors.vector
                 FROM active_vectors AS active
                 JOIN semantic_vectors AS vectors USING(vector_hash)",
            )
            .map_err(|err| err.to_string())?;
        let mut rows = statement.query([]).map_err(|err| err.to_string())?;
        let mut batch = Vec::with_capacity(effective_batch);
        while let Some(row) = rows.next().map_err(|err| err.to_string())? {
            batch.push(VectorRow {
                vector_hash: decode_key_blob(
                    row.get::<_, Vec<u8>>(0).map_err(|err| err.to_string())?,
                )?,
                code: row.get(1).map_err(|err| err.to_string())?,
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

    /// BM25 relevance per function symbol, with exact active-corpus statistics.
    pub fn bm25_symbol_scores(
        &self,
        match_query: &str,
        limit: usize,
    ) -> Result<Vec<(String, f64)>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.session.lock().expect("active session mutex poisoned");
        let mut statement = conn
            .prepare(
                "WITH hits(symbol, score) AS MATERIALIZED (
                     SELECT chunks.symbol, -bm25(bm25_idx)
                     FROM bm25_idx
                     JOIN active_occurrences AS occurrence
                       ON occurrence.occ_id = bm25_idx.rowid
                     JOIN active_files AS active USING(rel_path)
                     JOIN semantic_file_chunks AS chunks
                       ON chunks.blob_oid = active.blob_oid
                      AND chunks.rel_path = active.rel_path
                      AND chunks.chunk_ord = occurrence.chunk_ord
                     WHERE bm25_idx MATCH ?1
                 )
                 SELECT symbol, MAX(score) AS best_score
                 FROM hits
                 GROUP BY symbol
                 ORDER BY best_score DESC, symbol
                 LIMIT ?2",
            )
            .map_err(|err| err.to_string())?;
        let rows = statement
            .query_map(params![match_query, limit as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
            })
            .map_err(|err| err.to_string())?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| err.to_string())
    }

    pub fn occurrence_count(&self) -> usize {
        self.occ
            .iter()
            .filter(|occurrence| occurrence.is_some())
            .count()
    }
}

fn create_active_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TEMP TABLE active_files(
             rel_path TEXT PRIMARY KEY CHECK(length(rel_path) > 0),
             blob_oid TEXT NOT NULL CHECK(
                 length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'
             )
         ) WITHOUT ROWID, STRICT;

         CREATE TEMP TABLE active_occurrences(
             occ_id INTEGER PRIMARY KEY,
             rel_path TEXT NOT NULL,
             chunk_ord INTEGER NOT NULL,
             UNIQUE(rel_path, chunk_ord),
             FOREIGN KEY(rel_path) REFERENCES active_files(rel_path) ON DELETE CASCADE
         ) STRICT;

         CREATE TEMP TABLE active_vectors(
             vector_hash BLOB PRIMARY KEY CHECK(length(vector_hash) = 32)
         ) WITHOUT ROWID, STRICT;

         CREATE TEMP TABLE touched_vectors(
             vector_hash BLOB PRIMARY KEY CHECK(length(vector_hash) = 32)
         ) WITHOUT ROWID, STRICT;

         CREATE VIRTUAL TABLE temp.bm25_idx USING fts5(
             tokens, content='', contentless_delete=1
         );",
    )
    .map_err(|err| err.to_string())
}

fn load_all_occurrence_rows(conn: &Connection) -> Result<Vec<OccurrenceRow>, String> {
    let mut statement = conn
        .prepare(
            "SELECT occurrence.occ_id, occurrence.rel_path, chunks.symbol,
                    chunks.start_line, chunks.end_line, chunks.vector_hash
             FROM active_occurrences AS occurrence
             JOIN active_files AS active USING(rel_path)
             JOIN semantic_file_chunks AS chunks
               ON chunks.blob_oid = active.blob_oid
              AND chunks.rel_path = active.rel_path
              AND chunks.chunk_ord = occurrence.chunk_ord
             ORDER BY occurrence.occ_id",
        )
        .map_err(|err| err.to_string())?;
    let mut rows = statement.query([]).map_err(|err| err.to_string())?;
    let mut output = Vec::new();
    while let Some(row) = rows.next().map_err(|err| err.to_string())? {
        output.push(decode_occurrence_row(row)?);
    }
    Ok(output)
}

fn load_occurrence_rows_for_paths(
    conn: &Connection,
    paths: &HashSet<String>,
) -> Result<Vec<OccurrenceRow>, String> {
    let mut statement = conn
        .prepare(
            "SELECT occurrence.occ_id, occurrence.rel_path, chunks.symbol,
                    chunks.start_line, chunks.end_line, chunks.vector_hash
             FROM active_occurrences AS occurrence
             JOIN active_files AS active USING(rel_path)
             JOIN semantic_file_chunks AS chunks
               ON chunks.blob_oid = active.blob_oid
              AND chunks.rel_path = active.rel_path
              AND chunks.chunk_ord = occurrence.chunk_ord
             WHERE occurrence.rel_path = ?1
             ORDER BY occurrence.occ_id",
        )
        .map_err(|err| err.to_string())?;
    let mut output = Vec::new();
    for path in paths {
        let mut rows = statement.query([path]).map_err(|err| err.to_string())?;
        while let Some(row) = rows.next().map_err(|err| err.to_string())? {
            output.push(decode_occurrence_row(row)?);
        }
    }
    Ok(output)
}

fn decode_occurrence_row(row: &rusqlite::Row<'_>) -> Result<OccurrenceRow, String> {
    Ok(OccurrenceRow {
        occ_id: u32::try_from(row.get::<_, i64>(0).map_err(|err| err.to_string())?)
            .map_err(|err| format!("active occurrence rowid exceeds u32: {err}"))?,
        path: row.get(1).map_err(|err| err.to_string())?,
        symbol: row.get(2).map_err(|err| err.to_string())?,
        start_line: row.get(3).map_err(|err| err.to_string())?,
        end_line: row.get(4).map_err(|err| err.to_string())?,
        vector_hash: decode_key_blob(row.get::<_, Vec<u8>>(5).map_err(|err| err.to_string())?)?,
    })
}

fn decode_key_blob(blob: Vec<u8>) -> Result<Key, String> {
    blob.try_into().map_err(|value: Vec<u8>| {
        format!(
            "expected 32-byte semantic vector key, got {} bytes",
            value.len()
        )
    })
}

fn intern_path(paths: &mut Vec<Arc<str>>, ids: &mut HashMap<Arc<str>, u32>, path: &str) -> u32 {
    if let Some(id) = ids.get(path) {
        return *id;
    }
    let path: Arc<str> = Arc::from(path);
    let id = paths.len() as u32;
    paths.push(path.clone());
    ids.insert(path, id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FileChunkIn;

    fn chunk(symbol: &'static str, tokens: &'static str, hash: Key) -> FileChunkIn<'static> {
        FileChunkIn {
            chunk_ord: 0,
            symbol,
            start_line: Some(1),
            end_line: Some(3),
            fts_tokens: tokens,
            vector_hash: hash,
        }
    }

    fn fixture() -> (tempfile::TempDir, SemanticStore, &'static str, &'static str) {
        let temp = tempfile::tempdir().unwrap();
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        let first_oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second_oid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        store
            .upsert_vectors(&[([1; 32], vec![1.0, 0.0]), ([2; 32], vec![0.0, 1.0])])
            .unwrap();
        store
            .put_files(&[
                (
                    first_oid,
                    "src/active.rs",
                    Some("rust"),
                    &[chunk("active::run", "alpha active", [1; 32])],
                ),
                (
                    first_oid,
                    "src/decoy.rs",
                    Some("rust"),
                    &[chunk("decoy::run", "decoy only", [2; 32])],
                ),
                (
                    second_oid,
                    "src/active.rs",
                    Some("rust"),
                    &[chunk("replacement::run", "replacement beta", [2; 32])],
                ),
            ])
            .unwrap();
        (temp, store, first_oid, second_oid)
    }

    #[test]
    fn exact_path_membership_excludes_same_oid_decoys() {
        let (_temp, store, first_oid, _) = fixture();
        let index = ActiveIndex::build(
            &store,
            &HashMap::from([("src/active.rs".to_string(), first_oid.to_string())]),
        )
        .unwrap();

        assert_eq!(index.occurrence_count(), 1);
        assert_eq!(index.resolve(&[1; 32])[0].fqfn, "active::run");
        assert!(index.resolve(&[2; 32]).is_empty());
        let scores = index.bm25_symbol_scores("alpha", 10).unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].0, "active::run");
        assert!(index.bm25_symbol_scores("decoy", 10).unwrap().is_empty());

        let mut vectors = Vec::new();
        index
            .scan_vectors(1, &mut |batch| vectors.extend(batch))
            .unwrap();
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].vector_hash, [1; 32]);
    }

    #[test]
    fn active_connections_keep_independent_worktree_corpora() {
        let (_temp, store, first_oid, _) = fixture();
        let active = ActiveIndex::build(
            &store,
            &HashMap::from([("src/active.rs".to_string(), first_oid.to_string())]),
        )
        .unwrap();
        let decoy = ActiveIndex::build(
            &store,
            &HashMap::from([("src/decoy.rs".to_string(), first_oid.to_string())]),
        )
        .unwrap();

        assert!(!active.bm25_symbol_scores("alpha", 10).unwrap().is_empty());
        assert!(active.bm25_symbol_scores("decoy", 10).unwrap().is_empty());
        assert!(decoy.bm25_symbol_scores("alpha", 10).unwrap().is_empty());
        assert!(!decoy.bm25_symbol_scores("decoy", 10).unwrap().is_empty());
    }

    #[test]
    fn watcher_change_replaces_temp_and_rust_projections() {
        let (_temp, store, first_oid, second_oid) = fixture();
        let mut index = ActiveIndex::build(
            &store,
            &HashMap::from([("src/active.rs".to_string(), first_oid.to_string())]),
        )
        .unwrap();

        index
            .apply_changes(
                &HashMap::from([("src/active.rs".to_string(), second_oid.to_string())]),
                &[],
            )
            .unwrap();

        assert!(index.resolve(&[1; 32]).is_empty());
        assert_eq!(index.resolve(&[2; 32])[0].fqfn, "replacement::run");
        assert!(index.bm25_symbol_scores("alpha", 10).unwrap().is_empty());
        assert!(
            !index
                .bm25_symbol_scores("replacement", 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn watcher_removal_clears_temp_and_rust_projections() {
        let (_temp, store, first_oid, _) = fixture();
        let mut index = ActiveIndex::build(
            &store,
            &HashMap::from([("src/active.rs".to_string(), first_oid.to_string())]),
        )
        .unwrap();

        index
            .apply_changes(&HashMap::new(), &["src/active.rs".to_string()])
            .unwrap();

        assert_eq!(index.occurrence_count(), 0);
        assert!(index.resolve(&[1; 32]).is_empty());
        assert!(index.bm25_symbol_scores("alpha", 10).unwrap().is_empty());
        let mut vectors = Vec::new();
        index
            .scan_vectors(10, &mut |batch| vectors.extend(batch))
            .unwrap();
        assert!(vectors.is_empty());
    }

    #[test]
    fn planner_drives_chunk_lookup_from_active_files() {
        let (_temp, store, first_oid, _) = fixture();
        let index = ActiveIndex::build(
            &store,
            &HashMap::from([("src/active.rs".to_string(), first_oid.to_string())]),
        )
        .unwrap();
        let conn = index.session.lock().unwrap();
        let mut statement = conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT chunks.chunk_ord
                 FROM active_files AS active
                 JOIN semantic_file_chunks AS chunks
                   ON chunks.blob_oid = active.blob_oid
                  AND chunks.rel_path = active.rel_path",
            )
            .unwrap();
        let details = statement
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        assert!(details[0].contains("SCAN active"), "plan: {details:?}");
        assert!(
            details[1].contains("SEARCH chunks USING PRIMARY KEY"),
            "plan: {details:?}"
        );
    }
}
