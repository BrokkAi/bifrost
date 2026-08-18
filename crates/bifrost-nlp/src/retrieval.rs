//! Lazy, liveness-checked retrieval over the persistent semantic cache.
//!
//! The per-repository cache database already holds every chunk row and every
//! quantized vector. The only per-worktree fact is which `(rel_path, blob_oid)`
//! pairs are live right now, and the indexer's git identity walk already
//! produces that map. So retrieval keeps the map in memory, scores vectors
//! straight out of `semantic_vectors`, and resolves a matched vector to its
//! functions one hash at a time against `semantic_file_chunks`. Chunk rows that
//! belong to some other blob of a live path -- leftovers from an earlier version
//! of an edited file -- are skipped as the candidate list is walked.
//!
//! Nothing is projected, copied, or indexed at hydration time: opening a
//! `LiveSet` issues no query against any semantic content table.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};

use rayon::prelude::*;
use rusqlite::Connection;

use super::quant::CodeScorer;
use super::store::SemanticStore;

pub type Key = [u8; 32];

/// Most rows decoded into the reusable scan buffers before a chunk is scored.
///
/// The chunk is what bounds the scan's memory -- it holds its keys and all of
/// its code bytes at once -- and what makes each parallel unit a large slice of
/// many rows rather than a task per handful. Both caps matter: the row cap keeps
/// a small-dimension index from splitting into more units than it is worth, and
/// [`SCAN_CHUNK_BYTES`] keeps a large-dimension index from holding hundreds of
/// megabytes of codes at once.
const SCAN_CHUNK_ROWS: usize = 32_768;

/// Most quantized code bytes one chunk holds. A 512-dimension index stores
/// 528-byte codes, so its chunks are row-capped at about 17 MB; a
/// larger-dimension index takes fewer rows per chunk instead of more memory.
const SCAN_CHUNK_BYTES: usize = 16 << 20;

/// The exhaustive candidate scan. Kept as a constant so the EXPLAIN QUERY PLAN
/// pin cannot drift away from the statement the scan runs.
const VECTOR_SCAN_SQL: &str = "SELECT vector_hash, vector FROM semantic_vectors";

/// The pool the exhaustive scan scores on.
///
/// Deliberately not the global pool. Scoring 8,192-row batches with `par_iter`
/// there split each batch into a piece per worker across 120 threads, and the
/// 2026-08-16 firefox profile found 79-81 percent of a query's ~93 CPU seconds
/// inside `crossbeam_epoch::internal::Global::try_advance` and
/// `crossbeam_epoch::default::with_handle` -- pinning bookkeeping whose cost
/// grows with the number of registered participants and the number of parallel
/// operations, not with the work done. Few threads scoring few large slices
/// keeps both counts small, and it keeps the query off a pool an analyzer build
/// can saturate.
///
/// Eight threads is enough: the measured single-threaded floor for reading the
/// whole vector table is 0.84 s, so the scan is fetch-bound long before the
/// scoring threads are.
fn scan_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1)
            .min(8);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|index| format!("bifrost-vector-scan-{index}"))
            .build()
            .expect("build the semantic vector scan pool")
    })
}

/// A function occurrence that is live in this worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionHit {
    pub fqfn: String,
    pub path: String,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
}

/// One worktree's live content identity, plus a reader over the shared cache.
pub struct LiveSet {
    /// `rel_path -> blob_oid` for every analyzed file of this worktree.
    oids: HashMap<String, String>,
    session: Mutex<Connection>,
}

impl LiveSet {
    /// Hydrate for one worktree: take the identity map the caller already built
    /// and open a reader. This deliberately runs no query against
    /// `semantic_files`, `semantic_file_chunks`, or `semantic_vectors`.
    pub fn open(
        store: &SemanticStore,
        path_to_oid: HashMap<String, String>,
    ) -> Result<Self, String> {
        let session =
            brokk_bifrost_analysis::cache_db::open_readonly_temp_connection(store.db_path())?;
        Ok(Self {
            oids: path_to_oid,
            session: Mutex::new(session),
        })
    }

    /// Apply watcher changes. Liveness is a plain map, so there is no SQL here
    /// and nothing that can fail.
    pub fn apply_changes(&mut self, changed: &HashMap<String, String>, removed: &[String]) {
        for path in removed {
            self.oids.remove(path);
        }
        for (path, oid) in changed {
            self.oids.insert(path.clone(), oid.clone());
        }
    }

    /// Live analyzed files in this worktree. Exact and free; the live *chunk*
    /// count is not, because it is the workspace-wide join this design removes.
    pub fn live_file_count(&self) -> usize {
        self.oids.len()
    }

    fn is_live(&self, rel_path: &str, blob_oid: &str) -> bool {
        self.oids.get(rel_path).is_some_and(|live| live == blob_oid)
    }

    /// The `pool` best-scoring stored vectors, in descending score order.
    ///
    /// The scan is exhaustive over the persistent table -- it may include
    /// vectors that only dead blobs reference -- but the heap is bounded, so a
    /// query's peak memory does not grow with the corpus.
    ///
    /// Rows are read in chunks into two buffers the whole scan reuses: the key
    /// and code bytes are copied once out of the `rusqlite` row, which owns them
    /// only until the next row is stepped, so nothing is allocated per row. Each
    /// chunk is then scored as a few large slices on [`scan_pool`]. The result
    /// does not depend on either choice: every row is scored from the same
    /// bytes, and [`WeakestFirst`] orders candidates by score and then by key,
    /// so the bounded set and its order are fixed no matter what order
    /// candidates reach the heap.
    pub fn top_candidates(
        &self,
        scorer: &CodeScorer,
        pool: usize,
    ) -> Result<Vec<(Key, f32)>, String> {
        assert!(pool > 0, "candidate pool must be positive");
        let conn = self
            .session
            .lock()
            .expect("live set session mutex poisoned");
        let mut statement = conn
            .prepare(VECTOR_SCAN_SQL)
            .map_err(|err| err.to_string())?;
        let mut rows = statement.query([]).map_err(|err| err.to_string())?;

        let scan_pool = scan_pool();
        let mut heap: BinaryHeap<WeakestFirst> = BinaryHeap::with_capacity(pool + 1);
        let mut keys: Vec<Key> = Vec::new();
        let mut codes: Vec<u8> = Vec::new();
        // Every vector of one index carries the same quantized length, which is
        // what lets a chunk hold its codes in one flat buffer and split them by
        // stride. A row that disagrees is a corrupt or foreign row, and the
        // scorer would reject it anyway. The first row settles both the stride
        // and, with it, how many rows a chunk holds.
        let mut stride: Option<usize> = None;
        let mut chunk_rows = SCAN_CHUNK_ROWS;
        loop {
            keys.clear();
            codes.clear();
            while keys.len() < chunk_rows {
                let Some(row) = rows.next().map_err(|err| err.to_string())? else {
                    break;
                };
                let key = row
                    .get_ref(0)
                    .map_err(|err| err.to_string())?
                    .as_blob()
                    .map_err(|err| err.to_string())?;
                keys.push(decode_key(key)?);
                let code = row
                    .get_ref(1)
                    .map_err(|err| err.to_string())?
                    .as_blob()
                    .map_err(|err| err.to_string())?;
                match stride {
                    Some(stride) if stride != code.len() => {
                        return Err(format!(
                            "stored vector is {} bytes where this index stores {stride}",
                            code.len()
                        ));
                    }
                    Some(_) => {}
                    None => {
                        if code.is_empty() {
                            return Err("stored vector has no bytes".to_string());
                        }
                        stride = Some(code.len());
                        chunk_rows = SCAN_CHUNK_ROWS.min((SCAN_CHUNK_BYTES / code.len()).max(1));
                        keys.reserve(chunk_rows);
                        codes.reserve(chunk_rows * code.len());
                    }
                }
                codes.extend_from_slice(code);
            }
            if keys.is_empty() {
                break;
            }
            let stride = stride.expect("a non-empty chunk recorded its vector length");
            // One unit per pool thread: the whole point is a few large tasks.
            let rows_per_unit = keys.len().div_ceil(scan_pool.current_num_threads());
            let scored = scan_pool.install(|| {
                keys.par_chunks(rows_per_unit)
                    .zip(codes.par_chunks(rows_per_unit * stride))
                    .map(|(keys, codes)| {
                        let mut scored = Vec::with_capacity(keys.len());
                        for (key, code) in keys.iter().zip(codes.chunks_exact(stride)) {
                            scored.push(WeakestFirst {
                                score: scorer.score(code)?,
                                key: *key,
                            });
                        }
                        Ok(scored)
                    })
                    .collect::<Result<Vec<Vec<WeakestFirst>>, String>>()
            })?;
            for candidate in scored.into_iter().flatten() {
                if heap.len() < pool {
                    heap.push(candidate);
                } else if heap
                    .peek()
                    .is_some_and(|weakest| candidate.cmp(weakest) == Ordering::Less)
                {
                    heap.pop();
                    heap.push(candidate);
                }
            }
        }
        Ok(heap
            .into_sorted_vec()
            .into_iter()
            .map(|candidate| (candidate.key, candidate.score))
            .collect())
    }

    /// Function occurrences of one matched vector that are live in this
    /// worktree. This is the per-hit `(file, span)` lookup that replaces the
    /// upfront occurrences join; it reads only the rows of the matched hash.
    pub fn resolve_live(&self, vector_hash: &Key) -> Result<Vec<FunctionHit>, String> {
        let conn = self
            .session
            .lock()
            .expect("live set session mutex poisoned");
        let mut statement = conn
            .prepare_cached(CHUNKS_BY_VECTOR_SQL)
            .map_err(|err| err.to_string())?;
        let mut rows = statement
            .query([vector_hash.as_slice()])
            .map_err(|err| err.to_string())?;
        let mut hits = Vec::new();
        while let Some(row) = rows.next().map_err(|err| err.to_string())? {
            let blob_oid: String = row.get(0).map_err(|err| err.to_string())?;
            let path: String = row.get(1).map_err(|err| err.to_string())?;
            if !self.is_live(&path, &blob_oid) {
                continue;
            }
            hits.push(FunctionHit {
                fqfn: row.get(2).map_err(|err| err.to_string())?,
                path,
                start_line: row.get(3).map_err(|err| err.to_string())?,
                end_line: row.get(4).map_err(|err| err.to_string())?,
            });
        }
        Ok(hits)
    }

    #[cfg(test)]
    fn query_plan(&self, sql: &str, params: impl rusqlite::Params) -> Vec<String> {
        let conn = self
            .session
            .lock()
            .expect("live set session mutex poisoned");
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        statement
            .query_map(params, |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }
}

/// The per-hit lookup. Kept as a constant so the EXPLAIN QUERY PLAN pin cannot
/// drift away from the statement the query path actually runs.
const CHUNKS_BY_VECTOR_SQL: &str = "SELECT blob_oid, rel_path, symbol, start_line, end_line
     FROM semantic_file_chunks
     WHERE vector_hash = ?1";

/// A scored vector key ordered weakest-first, so a bounded `BinaryHeap` keeps
/// the candidate to evict at its root and `into_sorted_vec` yields best-first.
#[derive(Debug, PartialEq)]
struct WeakestFirst {
    score: f32,
    key: Key,
}

impl Eq for WeakestFirst {}

impl Ord for WeakestFirst {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .total_cmp(&self.score)
            .then_with(|| self.key.cmp(&other.key))
    }
}

impl PartialOrd for WeakestFirst {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn decode_key(blob: &[u8]) -> Result<Key, String> {
    Key::try_from(blob).map_err(|_| {
        format!(
            "expected 32-byte semantic vector key, got {} bytes",
            blob.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quant::query_scorer;
    use crate::store::FileChunkIn;

    const OLD_OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LIVE_OID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn chunk(symbol: &'static str, lines: (i64, i64), hash: Key) -> FileChunkIn<'static> {
        FileChunkIn {
            chunk_ord: 0,
            symbol,
            start_line: Some(lines.0),
            end_line: Some(lines.1),
            vector_hash: hash,
        }
    }

    /// A cache that carries chunks for an old blob of `src/active.rs` as well as
    /// the blob the worktree currently holds, plus an unrelated file.
    fn fixture() -> (tempfile::TempDir, SemanticStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        store
            .upsert_vectors(&[
                ([1; 32], vec![1.0, 0.0]),
                ([2; 32], vec![0.0, 1.0]),
                ([3; 32], vec![0.7, 0.7]),
            ])
            .unwrap();
        store
            .put_files(&[
                (
                    OLD_OID,
                    "src/active.rs",
                    Some("rust"),
                    &[chunk("stale::run", (1, 3), [1; 32])],
                ),
                (
                    LIVE_OID,
                    "src/active.rs",
                    Some("rust"),
                    &[chunk("active::run", (11, 19), [2; 32])],
                ),
                (
                    OLD_OID,
                    "src/decoy.rs",
                    Some("rust"),
                    &[chunk("decoy::run", (1, 2), [3; 32])],
                ),
            ])
            .unwrap();
        (temp, store)
    }

    fn live_worktree(store: &SemanticStore) -> LiveSet {
        LiveSet::open(
            store,
            HashMap::from([("src/active.rs".to_string(), LIVE_OID.to_string())]),
        )
        .unwrap()
    }

    #[test]
    fn dead_blob_candidate_is_skipped_for_the_live_one() {
        let (_temp, store) = fixture();
        let live = live_worktree(&store);

        // The old blob's chunk is still in the cache and its vector is still
        // scannable, but no live path resolves to that blob.
        assert!(live.resolve_live(&[1; 32]).unwrap().is_empty());
        assert!(live.resolve_live(&[3; 32]).unwrap().is_empty());

        let hits = live.resolve_live(&[2; 32]).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].fqfn, "active::run");
    }

    #[test]
    fn hits_carry_the_live_file_and_span() {
        let (_temp, store) = fixture();
        let live = live_worktree(&store);

        let hits = live.resolve_live(&[2; 32]).unwrap();
        assert_eq!(
            hits,
            vec![FunctionHit {
                fqfn: "active::run".to_string(),
                path: "src/active.rs".to_string(),
                start_line: Some(11),
                end_line: Some(19),
            }]
        );
    }

    /// Walking candidates in descending score and skipping dead ones must reach
    /// the live hit even though a dead blob's vector outranks it.
    #[test]
    fn candidate_walk_skips_dead_blobs_and_returns_the_next_live_hit() {
        let (_temp, store) = fixture();
        let live = live_worktree(&store);
        // Query aligned with the stale chunk's vector, so [1; 32] ranks first.
        let scorer = query_scorer(&[1.0, 0.0]);

        let candidates = live.top_candidates(&scorer, 8).unwrap();
        assert_eq!(candidates.len(), 3, "every stored vector is a candidate");
        assert_eq!(candidates[0].0, [1; 32], "the dead blob's vector ranks top");

        let resolved: Vec<FunctionHit> = candidates
            .iter()
            .flat_map(|(hash, _)| live.resolve_live(hash).unwrap())
            .collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].fqfn, "active::run");
    }

    #[test]
    fn top_candidates_are_bounded_and_ordered_best_first() {
        let (_temp, store) = fixture();
        let live = live_worktree(&store);
        let scorer = query_scorer(&[0.0, 1.0]);

        let candidates = live.top_candidates(&scorer, 2).unwrap();
        assert_eq!(candidates.len(), 2, "the pool bounds the returned set");
        assert_eq!(candidates[0].0, [2; 32]);
        assert!(candidates[0].1 >= candidates[1].1, "descending score");
    }

    /// The chunked, pooled scan must return exactly what scoring every stored
    /// vector one at a time returns. The corpus is sized to cross a chunk
    /// boundary, so buffer reuse, the stride split and the per-unit slicing are
    /// all exercised; the scores are compared bit for bit.
    #[test]
    fn the_chunked_scan_matches_a_row_at_a_time_scan_across_chunk_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let store = SemanticStore::open(&temp.path().join("cache.db")).unwrap();
        let rows = SCAN_CHUNK_ROWS + 1_237;
        let vectors: Vec<(Key, Vec<f32>)> = (0..rows)
            .map(|index| {
                let mut key = [0u8; 32];
                key[..8].copy_from_slice(&(index as u64).to_be_bytes());
                // A deterministic spread of directions so the ranking is not a
                // tie and the pool boundary is meaningful.
                let angle = index as f32 * 0.013;
                (key, vec![angle.cos(), angle.sin()])
            })
            .collect();
        store.upsert_vectors(&vectors).unwrap();
        let live = LiveSet::open(&store, HashMap::new()).unwrap();
        let scorer = query_scorer(&[1.0, 0.0]);

        let expected = {
            let conn =
                brokk_bifrost_analysis::cache_db::open_readonly_temp_connection(store.db_path())
                    .unwrap();
            let mut statement = conn.prepare(VECTOR_SCAN_SQL).unwrap();
            let mut scored: Vec<(Key, f32)> = statement
                .query_map([], |row| {
                    let key = decode_key(row.get_ref(0).unwrap().as_blob().unwrap()).unwrap();
                    let code: Vec<u8> = row.get(1).unwrap();
                    Ok((key, scorer.score(&code).unwrap()))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            scored.sort_by(|left, right| {
                right
                    .1
                    .total_cmp(&left.1)
                    .then_with(|| left.0.cmp(&right.0))
            });
            scored.truncate(64);
            scored
        };

        assert_eq!(live.top_candidates(&scorer, 64).unwrap(), expected);
    }

    #[test]
    fn watcher_changes_move_liveness_without_touching_sql() {
        let (_temp, store) = fixture();
        let mut live = live_worktree(&store);

        live.apply_changes(
            &HashMap::from([("src/active.rs".to_string(), OLD_OID.to_string())]),
            &[],
        );
        assert_eq!(live.resolve_live(&[1; 32]).unwrap()[0].fqfn, "stale::run");
        assert!(live.resolve_live(&[2; 32]).unwrap().is_empty());

        live.apply_changes(&HashMap::new(), &["src/active.rs".to_string()]);
        assert_eq!(live.live_file_count(), 0);
        assert!(live.resolve_live(&[1; 32]).unwrap().is_empty());
    }

    /// Hydration must not read any semantic content table. Renaming both of
    /// them away proves it structurally: `LiveSet::open` still succeeds.
    #[test]
    fn hydration_reads_no_semantic_content_table() {
        let (temp, store) = fixture();
        let db_path = temp.path().join("cache.db");
        drop(store);
        {
            let writer = Connection::open(&db_path).unwrap();
            writer
                .execute_batch(
                    "ALTER TABLE semantic_file_chunks RENAME TO semantic_file_chunks_hidden;
                     ALTER TABLE semantic_files RENAME TO semantic_files_hidden;",
                )
                .unwrap();
        }
        let store = SemanticStore::open(&db_path).unwrap();

        let live = LiveSet::open(
            &store,
            HashMap::from([("src/active.rs".to_string(), LIVE_OID.to_string())]),
        )
        .expect("hydration must not depend on the chunk tables");
        assert_eq!(live.live_file_count(), 1);
    }

    #[test]
    fn per_hit_lookup_searches_the_vector_index() {
        let (_temp, store) = fixture();
        let live = live_worktree(&store);

        let plan = live.query_plan(CHUNKS_BY_VECTOR_SQL, [[2u8; 32].as_slice()]);
        assert_eq!(plan.len(), 1, "one step, no join: {plan:?}");
        assert!(
            plan[0]
                .contains("SEARCH semantic_file_chunks USING INDEX semantic_file_chunks_by_vector"),
            "plan: {plan:?}"
        );
    }

    #[test]
    fn candidate_scan_is_a_bare_vector_scan() {
        let (_temp, store) = fixture();
        let live = live_worktree(&store);

        let plan = live.query_plan(VECTOR_SCAN_SQL, []);
        assert_eq!(plan.len(), 1, "one step, no join: {plan:?}");
        assert!(plan[0].contains("SCAN semantic_vectors"), "plan: {plan:?}");
    }
}
