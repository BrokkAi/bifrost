//! In-memory active index: the per-worktree join of git (`path → oid`) and the
//! content-addressed cache (`oid → chunks`). It resolves a retrieval hit
//! (`composed_hash`) back to `fq function name + file + lines`, and holds a
//! private bm25 FTS so corpus statistics equal exactly this working tree.
//!
//! Nothing here is persisted. It is rebuilt eagerly at indexer startup and
//! patched incrementally on watcher deltas. Paths are interned once (`file_id`)
//! so the resident cost is dominated by metadata, not duplicated path text.
//!
//! The bm25 `Connection` is `Send` but not `Sync`, so it lives behind a `Mutex`;
//! that lets the whole `ActiveIndex` sit in an `RwLock` shared between the worker
//! (writes) and query threads (reads).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, params};

use super::store::{BlobChunkRow, SemanticStore};

type Key = [u8; 32];

struct Occurrence {
    file_id: u32,
    fqfn: Option<String>,
    start_line: Option<i64>,
    end_line: Option<i64>,
    composed_hash: Key,
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
    /// `occ[occ_id]`; `None` is a tombstone. `occ_id` doubles as the bm25 rowid.
    occ: Vec<Option<Occurrence>>,
    free: Vec<u32>,
    by_composed: HashMap<Key, Vec<u32>>,
    by_file: HashMap<u32, Vec<u32>>,
    active_hashes: HashSet<Key>,
    bm25: Mutex<Connection>,
}

impl ActiveIndex {
    /// Build the active index for a worktree from its `path -> blob_oid` map.
    /// Blobs must already be materialized in `store`.
    pub fn build(
        store: &SemanticStore,
        path_to_oid: &HashMap<String, String>,
    ) -> Result<Self, String> {
        let mut index = ActiveIndex {
            paths: Vec::new(),
            path_ids: HashMap::new(),
            occ: Vec::new(),
            free: Vec::new(),
            by_composed: HashMap::new(),
            by_file: HashMap::new(),
            active_hashes: HashSet::new(),
            bm25: Mutex::new(open_bm25()?),
        };

        let oids: Vec<String> = {
            let mut set: HashSet<&String> = HashSet::new();
            path_to_oid
                .values()
                .filter(|o| set.insert(*o))
                .cloned()
                .collect()
        };
        let rows = store.chunks_for_oids(&oids).map_err(|e| e.to_string())?;
        let grouped = group_by_oid(rows);

        let mut docs: Vec<(i64, String)> = Vec::new();
        for (path, oid) in path_to_oid {
            let Some(rows) = grouped.get(oid) else {
                continue;
            };
            let file_id = intern_path(&mut index.paths, &mut index.path_ids, path);
            for row in rows {
                let occ_id = index.occ.len() as u32;
                index.occ.push(Some(Occurrence {
                    file_id,
                    fqfn: row.symbol.clone(),
                    start_line: row.start_line,
                    end_line: row.end_line,
                    composed_hash: row.composed_hash,
                }));
                index
                    .by_composed
                    .entry(row.composed_hash)
                    .or_default()
                    .push(occ_id);
                index.by_file.entry(file_id).or_default().push(occ_id);
                index.active_hashes.insert(row.composed_hash);
                docs.push((occ_id as i64, row.fts_tokens.clone()));
            }
        }

        // Bulk-insert bm25 docs in one transaction (lock not held above).
        {
            let mut conn = index.bm25.lock().expect("bm25 mutex poisoned");
            let tx = conn.transaction().map_err(|e| e.to_string())?;
            {
                let mut insert = tx
                    .prepare("INSERT INTO bm25_idx(rowid, tokens) VALUES(?1, ?2)")
                    .map_err(|e| e.to_string())?;
                for (occ_id, tokens) in &docs {
                    insert
                        .execute(params![occ_id, tokens])
                        .map_err(|e| e.to_string())?;
                }
            }
            tx.commit().map_err(|e| e.to_string())?;
        }

        store
            .set_active_composed_hashes(&index.active_hashes)
            .map_err(|e| e.to_string())?;
        Ok(index)
    }

    /// Patch the index for a watcher delta. `changed` is `path -> new oid` for
    /// added/modified files (their blobs already materialized); `removed` are
    /// deleted paths. Keeps the store's active set in sync.
    pub fn apply_changes(
        &mut self,
        store: &SemanticStore,
        changed: &HashMap<String, String>,
        removed: &[String],
    ) -> Result<(), String> {
        let mut touched: HashSet<Key> = HashSet::new();

        for path in removed.iter().chain(changed.keys()) {
            self.evict_path(path, &mut touched)?;
        }

        if !changed.is_empty() {
            let oids: Vec<String> = changed.values().cloned().collect();
            let rows = store.chunks_for_oids(&oids).map_err(|e| e.to_string())?;
            let grouped = group_by_oid(rows);
            for (path, oid) in changed {
                if let Some(rows) = grouped.get(oid) {
                    self.add_rows(path, rows, &mut touched)?;
                }
            }
        }

        let to_remove: Vec<Key> = touched
            .iter()
            .copied()
            .filter(|h| !self.active_hashes.contains(h))
            .collect();
        let to_add: Vec<Key> = touched
            .iter()
            .copied()
            .filter(|h| self.active_hashes.contains(h))
            .collect();
        store
            .remove_active_composed(&to_remove)
            .map_err(|e| e.to_string())?;
        store
            .add_active_composed(&to_add)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn evict_path(&mut self, path: &str, touched: &mut HashSet<Key>) -> Result<(), String> {
        let Some(&file_id) = self.path_ids.get(path) else {
            return Ok(());
        };
        let Some(occ_ids) = self.by_file.remove(&file_id) else {
            return Ok(());
        };
        for occ_id in occ_ids {
            let Some(occ) = self.occ[occ_id as usize].take() else {
                continue;
            };
            self.free.push(occ_id);
            self.bm25
                .lock()
                .expect("bm25 mutex poisoned")
                .execute(
                    "DELETE FROM bm25_idx WHERE rowid = ?1",
                    params![occ_id as i64],
                )
                .map_err(|e| e.to_string())?;
            if let Some(bucket) = self.by_composed.get_mut(&occ.composed_hash) {
                bucket.retain(|id| *id != occ_id);
                if bucket.is_empty() {
                    self.by_composed.remove(&occ.composed_hash);
                    self.active_hashes.remove(&occ.composed_hash);
                }
            }
            touched.insert(occ.composed_hash);
        }
        Ok(())
    }

    fn add_rows(
        &mut self,
        path: &str,
        rows: &[BlobChunkRow],
        touched: &mut HashSet<Key>,
    ) -> Result<(), String> {
        let file_id = intern_path(&mut self.paths, &mut self.path_ids, path);
        for row in rows {
            let occurrence = Occurrence {
                file_id,
                fqfn: row.symbol.clone(),
                start_line: row.start_line,
                end_line: row.end_line,
                composed_hash: row.composed_hash,
            };
            let occ_id = match self.free.pop() {
                Some(id) => {
                    self.occ[id as usize] = Some(occurrence);
                    id
                }
                None => {
                    let id = self.occ.len() as u32;
                    self.occ.push(Some(occurrence));
                    id
                }
            };
            self.bm25
                .lock()
                .expect("bm25 mutex poisoned")
                .execute(
                    "INSERT INTO bm25_idx(rowid, tokens) VALUES(?1, ?2)",
                    params![occ_id as i64, row.fts_tokens],
                )
                .map_err(|e| e.to_string())?;
            self.by_composed
                .entry(row.composed_hash)
                .or_default()
                .push(occ_id);
            self.by_file.entry(file_id).or_default().push(occ_id);
            self.active_hashes.insert(row.composed_hash);
            touched.insert(row.composed_hash);
        }
        Ok(())
    }

    /// Function occurrences (with an fqfn) for a hit's `composed_hash`. Summary
    /// chunks (no fqfn) are skipped — they are search context, not results.
    pub fn resolve(&self, composed_hash: &Key) -> Vec<FunctionHit<'_>> {
        let Some(ids) = self.by_composed.get(composed_hash) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| {
                let occ = self.occ[*id as usize].as_ref()?;
                let fqfn = occ.fqfn.as_deref()?;
                Some(FunctionHit {
                    fqfn,
                    path: &self.paths[occ.file_id as usize],
                    start_line: occ.start_line,
                    end_line: occ.end_line,
                })
            })
            .collect()
    }

    /// BM25 relevance per function symbol (fqfn), max over a symbol's chunks.
    pub fn bm25_symbol_scores(
        &self,
        match_query: &str,
        limit: usize,
    ) -> Result<Vec<(String, f64)>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.bm25.lock().expect("bm25 mutex poisoned");
        let mut stmt = conn
            .prepare("SELECT rowid, bm25(bm25_idx) FROM bm25_idx WHERE bm25_idx MATCH ?1")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([match_query]).map_err(|e| e.to_string())?;
        let mut symbol_scores: HashMap<String, f64> = HashMap::new();
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let occ_id: i64 = row.get(0).map_err(|e| e.to_string())?;
            let score: f64 = -row.get::<_, f64>(1).map_err(|e| e.to_string())?;
            if let Some(Some(occ)) = self.occ.get(occ_id as usize)
                && let Some(fqfn) = &occ.fqfn
            {
                symbol_scores
                    .entry(fqfn.clone())
                    .and_modify(|best| {
                        if score > *best {
                            *best = score;
                        }
                    })
                    .or_insert(score);
            }
        }
        drop(rows);
        drop(stmt);
        let mut scored: Vec<(String, f64)> = symbol_scores.into_iter().collect();
        scored.sort_by(|(sa, va), (sb, vb)| {
            vb.partial_cmp(va)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| sa.cmp(sb))
        });
        scored.truncate(limit);
        Ok(scored)
    }

    pub fn occurrence_count(&self) -> usize {
        self.occ.iter().filter(|o| o.is_some()).count()
    }
}

fn open_bm25() -> Result<Connection, String> {
    let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE bm25_idx USING fts5(tokens, content='', contentless_delete=1);",
    )
    .map_err(|e| e.to_string())?;
    Ok(conn)
}

fn intern_path(paths: &mut Vec<Arc<str>>, ids: &mut HashMap<Arc<str>, u32>, path: &str) -> u32 {
    if let Some(id) = ids.get(path) {
        return *id;
    }
    let arc: Arc<str> = Arc::from(path);
    let id = paths.len() as u32;
    paths.push(arc.clone());
    ids.insert(arc, id);
    id
}

fn group_by_oid(rows: Vec<BlobChunkRow>) -> HashMap<String, Vec<BlobChunkRow>> {
    let mut grouped: HashMap<String, Vec<BlobChunkRow>> = HashMap::new();
    for row in rows {
        grouped.entry(row.blob_oid.clone()).or_default().push(row);
    }
    grouped
}
