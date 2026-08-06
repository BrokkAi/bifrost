//! Shared opportunistic GC driver for the unified bifrost cache DB.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Mutex, MutexGuard, OnceLock};

use git2::Repository;
use growable_bloom_filter::GrowableBloom;
use rusqlite::{Connection, TransactionBehavior};

use crate::{cache_db, gitblob};

pub use crate::cache_db::{VERSION_STORE_GRACE_SECS, sweep_disused_version_stores};

/// git-gc.auto-style blob growth threshold.
pub const GC_AUTO_BLOB_THRESHOLD: i64 = 5000;
/// Time-based fallback sweep interval, used only when the registry has grown.
pub const GC_MIN_INTERVAL_SECS: i64 = 6 * 3600;
const GC_CLAIM_TTL_SECS: i64 = 3600;

static AUTO_BLOB_THRESHOLD: AtomicI64 = AtomicI64::new(GC_AUTO_BLOB_THRESHOLD);
static MIN_INTERVAL_SECS: AtomicI64 = AtomicI64::new(GC_MIN_INTERVAL_SECS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcOutcome {
    pub ran: bool,
    pub semantic_dropped: usize,
    pub analyzer_dropped: usize,
    pub total_blobs_after: i64,
    pub version_stores_removed: usize,
}

impl GcOutcome {
    pub fn skipped(total_blobs_after: i64) -> Self {
        Self {
            ran: false,
            semantic_dropped: 0,
            analyzer_dropped: 0,
            total_blobs_after,
            version_stores_removed: 0,
        }
    }
}

#[derive(Debug)]
struct GcClaim {
    db_path: std::path::PathBuf,
}

/// Collect against a unified cache DB. `db_path` is all collection needs from
/// either store: the registry tables it sweeps are reached through that path,
/// never through the store handle, which is why neither the semantic store nor
/// the analyzer store has to be visible from this crate.
pub fn maybe_gc(db_path: &Path, repo: &Repository) -> Result<GcOutcome, String> {
    // A deliberately cross-repository cache cannot be collected from the
    // reachability graph of whichever repository happens to open it first.
    // Evaluation and fleet operators that provide such a cache can disable
    // opportunistic collection while retaining the explicit force-GC API.
    if !automatic_gc_enabled(std::env::var_os("BIFROST_CACHE_GC").as_deref()) {
        return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
    }
    run_gc(db_path, repo, false)
}

pub fn force_gc(db_path: &Path, repo: &Repository) -> Result<GcOutcome, String> {
    run_gc(db_path, repo, true)
}

fn run_gc(db_path: &Path, repo: &Repository, force: bool) -> Result<GcOutcome, String> {
    let Some(claim) = try_claim_gc(db_path, force)? else {
        return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
    };
    match sweep_with_claim(&claim, repo) {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            clear_gc_claim(db_path)?;
            Err(err)
        }
    }
}

fn automatic_gc_enabled(value: Option<&OsStr>) -> bool {
    !matches!(
        value.and_then(OsStr::to_str),
        Some("0" | "off" | "disabled")
    )
}

fn sweep_with_claim(claim: &GcClaim, repo: &Repository) -> Result<GcOutcome, String> {
    // Snapshot the rows eligible for this collection before walking Git. A
    // workspace build may persist another blob while the reachability walk is
    // in flight; that new row must belong to the next collection, even when
    // the walk started before its working-tree or ref update became visible.
    let mut conn = cache_db::open_unified_connection(&claim.db_path)?;
    conn.pragma_update(None, "temp_store", "FILE")
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    conn.execute_batch(
        "CREATE TEMP TABLE gc_semantic_candidates(
           blob_oid TEXT PRIMARY KEY
         ) WITHOUT ROWID;
         INSERT INTO gc_semantic_candidates(blob_oid)
           SELECT DISTINCT blob_oid FROM semantic_files;
         CREATE TEMP TABLE gc_analyzer_candidates(
           blob_oid TEXT NOT NULL,
           lang TEXT NOT NULL,
           generation INTEGER NOT NULL,
           PRIMARY KEY(blob_oid, lang, generation)
         ) WITHOUT ROWID;
         INSERT INTO gc_analyzer_candidates(blob_oid, lang, generation)
           SELECT blobs.blob_oid, blobs.lang, blobs.generation
           FROM blobs
           LEFT JOIN analysis_epochs AS epochs ON epochs.lang = blobs.lang
           WHERE blobs.generation = COALESCE(epochs.generation, 0);",
    )
    .map_err(|err| format!("cache GC SQLite error: {err}"))?;

    let live = live_bloom(repo)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    let dead_semantic = {
        let mut stmt = tx
            .prepare("SELECT blob_oid FROM gc_semantic_candidates")
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("cache GC SQLite error: {err}"))?
            .into_iter()
            .filter(|oid| !live.contains(oid))
            .collect::<Vec<_>>()
    };
    {
        let mut delete = tx
            .prepare("DELETE FROM semantic_files WHERE blob_oid = ?1")
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        for oid in &dead_semantic {
            delete
                .execute([oid])
                .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        }
    }
    tx.execute(
        "DELETE FROM semantic_vectors
         WHERE vector_hash NOT IN (SELECT vector_hash FROM semantic_file_chunks)",
        [],
    )
    .map_err(|err| format!("cache GC SQLite error: {err}"))?;

    let dead_analyzer = {
        let mut stmt = tx
            .prepare("SELECT blob_oid, lang, generation FROM gc_analyzer_candidates")
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("cache GC SQLite error: {err}"))?
            .into_iter()
            .filter(|(oid, _, _)| !live.contains(oid))
            .collect::<Vec<_>>()
    };
    let analyzer_dropped = delete_analyzer_candidates(&tx, &dead_analyzer)?;
    tx.commit()
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    conn.pragma_update(None, "incremental_vacuum", 0)
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;

    let semantic_dropped = dead_semantic.len();
    let total_blobs_after = finish_gc(&claim.db_path)?;
    // Row collection and file collection answer the same question about
    // different granularities, and both belong under the claim: one sweeper at
    // a time, at the cadence the claim already paces.
    let cache_dir = claim
        .db_path
        .parent()
        .expect("a cache DB path has a parent directory");
    let version_stores_removed = sweep_disused_version_stores(cache_dir)?.len();
    Ok(GcOutcome {
        ran: true,
        semantic_dropped,
        analyzer_dropped,
        total_blobs_after,
        version_stores_removed,
    })
}

fn delete_analyzer_candidates(
    tx: &rusqlite::Transaction<'_>,
    candidates: &[(String, String, i64)],
) -> Result<usize, String> {
    let mut delete = tx
        .prepare(
            "DELETE FROM blobs
             WHERE blob_oid = ?1 AND lang = ?2 AND generation = ?3",
        )
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    let mut dropped = 0usize;
    for (oid, lang, generation) in candidates {
        dropped += delete
            .execute((oid, lang, generation))
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    }
    Ok(dropped)
}

fn live_bloom(repo: &Repository) -> Result<GrowableBloom, String> {
    let mut live = gitblob::reachable_bloom(repo)?;
    for root in gitblob::worktree_roots(repo)? {
        if let Ok(working_tree) = gitblob::existing_working_tree_oids(&root) {
            for oid in working_tree {
                live.insert(oid);
            }
        }
    }
    Ok(live)
}

fn try_claim_gc(db_path: &Path, force: bool) -> Result<Option<GcClaim>, String> {
    let mut conn = cache_db::open_unified_connection(db_path)?;
    let now = cache_db::now_unix_seconds();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    let current_total = total_blob_count_conn(&tx)?;
    let claim_until: i64 = tx
        .query_row(
            "SELECT gc_claim_until FROM cache_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    if claim_until > now {
        tx.commit()
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        return Ok(None);
    }
    if !force && !gc_due_tx(&tx, current_total, now)? {
        tx.commit()
            .map_err(|err| format!("cache GC SQLite error: {err}"))?;
        return Ok(None);
    }
    tx.execute(
        "UPDATE cache_state SET gc_claim_until = ?1 WHERE id = 1",
        [now + GC_CLAIM_TTL_SECS],
    )
    .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    tx.commit()
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    Ok(Some(GcClaim {
        db_path: db_path.to_path_buf(),
    }))
}

fn gc_due_tx(tx: &rusqlite::Transaction<'_>, current_total: i64, now: i64) -> Result<bool, String> {
    let (last_gc_at, blobs_at_last_gc): (i64, i64) = tx
        .query_row(
            "SELECT last_gc_at, blobs_at_last_gc FROM cache_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    let growth = current_total - blobs_at_last_gc;
    if growth <= 0 {
        return Ok(false);
    }
    if growth > AUTO_BLOB_THRESHOLD.load(Ordering::Relaxed) {
        return Ok(true);
    }
    Ok(now.saturating_sub(last_gc_at) >= MIN_INTERVAL_SECS.load(Ordering::Relaxed))
}

fn finish_gc(db_path: &Path) -> Result<i64, String> {
    let mut conn = cache_db::open_unified_connection(db_path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    let total = total_blob_count_conn(&tx)?;
    let now = cache_db::now_unix_seconds();
    tx.execute(
        "UPDATE cache_state
         SET last_gc_at = ?1, blobs_at_last_gc = ?2, gc_claim_until = 0
         WHERE id = 1",
        (now, total),
    )
    .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    tx.commit()
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    conn.pragma_update(None, "incremental_vacuum", 0)
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    Ok(total)
}

fn clear_gc_claim(db_path: &Path) -> Result<(), String> {
    let mut conn = cache_db::open_unified_connection(db_path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    tx.execute("UPDATE cache_state SET gc_claim_until = 0 WHERE id = 1", [])
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    tx.commit()
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    Ok(())
}

fn total_blob_count(db_path: &Path) -> Result<i64, String> {
    let conn = cache_db::open_unified_connection(db_path)?;
    total_blob_count_conn(&conn)
}

fn total_blob_count_conn(conn: &Connection) -> Result<i64, String> {
    conn.query_row(
        "SELECT
           (SELECT COUNT(DISTINCT blob_oid) FROM semantic_files) +
           (SELECT COUNT(*) FROM blobs)",
        [],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache GC SQLite error: {err}"))
}

#[cfg(any(test, feature = "test-support"))]
pub struct GcTuningGuard {
    previous_threshold: i64,
    previous_interval: i64,
    _lock: MutexGuard<'static, ()>,
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for GcTuningGuard {
    fn drop(&mut self) {
        AUTO_BLOB_THRESHOLD.store(self.previous_threshold, Ordering::Relaxed);
        MIN_INTERVAL_SECS.store(self.previous_interval, Ordering::Relaxed);
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn set_tuning_for_test(auto_threshold: i64, min_interval_secs: i64) -> GcTuningGuard {
    let lock = gc_tuning_lock()
        .lock()
        .expect("GC tuning test mutex poisoned");
    let previous_threshold = AUTO_BLOB_THRESHOLD.swap(auto_threshold, Ordering::Relaxed);
    let previous_interval = MIN_INTERVAL_SECS.swap(min_interval_secs, Ordering::Relaxed);
    GcTuningGuard {
        previous_threshold,
        previous_interval,
        _lock: lock,
    }
}

#[cfg(any(test, feature = "test-support"))]
fn gc_tuning_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(any(test, feature = "test-support"))]
pub fn set_accounting_for_test(
    db_path: &Path,
    last_gc_at: i64,
    blobs_at_last_gc: i64,
) -> Result<(), String> {
    let mut conn = cache_db::open_unified_connection(db_path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    tx.execute(
        "UPDATE cache_state
         SET last_gc_at = ?1, blobs_at_last_gc = ?2, gc_claim_until = 0
         WHERE id = 1",
        (last_gc_at, blobs_at_last_gc),
    )
    .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    tx.commit()
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub fn total_blob_count_for_test(db_path: &Path) -> Result<i64, String> {
    total_blob_count(db_path)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    #[test]
    fn automatic_gc_can_be_explicitly_disabled() {
        assert!(automatic_gc_enabled(None));
        assert!(automatic_gc_enabled(Some(OsStr::new("on"))));
        assert!(!automatic_gc_enabled(Some(OsStr::new("0"))));
        assert!(!automatic_gc_enabled(Some(OsStr::new("off"))));
        assert!(!automatic_gc_enabled(Some(OsStr::new("disabled"))));
    }

    #[test]
    fn analyzer_gc_candidate_cannot_delete_newer_generation_replacement() {
        let mut conn = Connection::open_in_memory().unwrap();
        cache_db::configure_connection(&mut conn).unwrap();
        cache_db::migrate(&mut conn).unwrap();
        let oid = "1111111111111111111111111111111111111111";
        conn.execute(
            "INSERT INTO analysis_epochs(lang, epoch, generation)
             VALUES('java', 'a', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 1)",
            [oid],
        )
        .unwrap();
        let candidate = vec![(oid.to_string(), "java".to_string(), 1)];

        conn.execute(
            "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
            [oid],
        )
        .unwrap();
        conn.execute(
            "UPDATE analysis_epochs SET epoch = 'b', generation = 2 WHERE lang = 'java'",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 2)",
            [oid],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        assert_eq!(delete_analyzer_candidates(&tx, &candidate).unwrap(), 0);
        tx.commit().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT generation FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                [oid],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
    }
}
