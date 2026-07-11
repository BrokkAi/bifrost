//! Shared opportunistic GC driver for the unified bifrost cache DB.

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use git2::Repository;
use growable_bloom_filter::GrowableBloom;
use rusqlite::{Connection, TransactionBehavior};

use crate::analyzer::store::AnalyzerStore;
use crate::{cache_db, gitblob};

#[cfg(feature = "nlp")]
use crate::nlp::store::SemanticStore;

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
}

impl GcOutcome {
    fn skipped(total_blobs_after: i64) -> Self {
        Self {
            ran: false,
            semantic_dropped: 0,
            analyzer_dropped: 0,
            total_blobs_after,
        }
    }
}

#[derive(Debug)]
struct GcClaim {
    db_path: std::path::PathBuf,
}

#[cfg(feature = "nlp")]
pub fn maybe_gc_for_semantic(
    store: &SemanticStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    run_gc(store.db_path(), repo, Some(store), None, false)
}

#[cfg(feature = "nlp")]
pub fn force_gc_for_semantic(
    store: &SemanticStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    run_gc(store.db_path(), repo, Some(store), None, true)
}

pub fn maybe_gc_for_analyzer(
    store: &AnalyzerStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    let Some(db_path) = store.db_path() else {
        return Ok(GcOutcome::skipped(0));
    };
    run_gc(db_path, repo, None, Some(store), false)
}

pub fn force_gc_for_analyzer(
    store: &AnalyzerStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    let Some(db_path) = store.db_path() else {
        return Ok(GcOutcome::skipped(0));
    };
    run_gc(db_path, repo, None, Some(store), true)
}

fn run_gc(
    db_path: &Path,
    repo: &Repository,
    #[cfg(feature = "nlp")] semantic_store: Option<&SemanticStore>,
    #[cfg(not(feature = "nlp"))] _semantic_store: Option<&()>,
    analyzer_store: Option<&AnalyzerStore>,
    force: bool,
) -> Result<GcOutcome, String> {
    let Some(claim) = try_claim_gc(db_path, force)? else {
        return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
    };
    #[cfg(feature = "nlp")]
    let sweep = sweep_with_claim(&claim, repo, semantic_store, analyzer_store);
    #[cfg(not(feature = "nlp"))]
    let sweep = sweep_with_claim(&claim, repo, None, analyzer_store);
    match sweep {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            clear_gc_claim(db_path)?;
            Err(err)
        }
    }
}

fn sweep_with_claim(
    claim: &GcClaim,
    repo: &Repository,
    #[cfg(feature = "nlp")] semantic_store: Option<&SemanticStore>,
    #[cfg(not(feature = "nlp"))] _semantic_store: Option<&()>,
    analyzer_store: Option<&AnalyzerStore>,
) -> Result<GcOutcome, String> {
    let live = live_bloom(repo)?;

    #[cfg(feature = "nlp")]
    let semantic_dropped = match semantic_store {
        Some(store) => store
            .gc_with(|oid| live.contains(oid))
            .map_err(|err| err.to_string())?,
        None => {
            let store = SemanticStore::open(&claim.db_path).map_err(|err| err.to_string())?;
            store
                .gc_with(|oid| live.contains(oid))
                .map_err(|err| err.to_string())?
        }
    };
    #[cfg(not(feature = "nlp"))]
    let semantic_dropped = 0;

    let analyzer_dropped = match analyzer_store {
        Some(store) => store
            .gc_with(|oid| live.contains(oid))
            .map_err(|err| err.to_string())?,
        None => {
            let store =
                AnalyzerStore::open_persistent(&claim.db_path).map_err(|err| err.to_string())?;
            store
                .gc_with(|oid| live.contains(oid))
                .map_err(|err| err.to_string())?
        }
    };

    let total_blobs_after = finish_gc(&claim.db_path)?;
    Ok(GcOutcome {
        ran: true,
        semantic_dropped,
        analyzer_dropped,
        total_blobs_after,
    })
}

fn live_bloom(repo: &Repository) -> Result<GrowableBloom, String> {
    let mut live = gitblob::reachable_bloom(repo)?;
    for root in gitblob::worktree_roots(repo)? {
        if let Ok(dirty) = gitblob::uncommitted_oids(&root) {
            for oid in dirty {
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
           (SELECT COUNT(*) FROM semantic_blobs) +
           (SELECT COUNT(*) FROM blobs)",
        [],
        |row| row.get(0),
    )
    .map_err(|err| format!("cache GC SQLite error: {err}"))
}

#[doc(hidden)]
pub struct GcTuningGuard {
    previous_threshold: i64,
    previous_interval: i64,
    _lock: MutexGuard<'static, ()>,
}

impl Drop for GcTuningGuard {
    fn drop(&mut self) {
        AUTO_BLOB_THRESHOLD.store(self.previous_threshold, Ordering::Relaxed);
        MIN_INTERVAL_SECS.store(self.previous_interval, Ordering::Relaxed);
    }
}

#[doc(hidden)]
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

fn gc_tuning_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[doc(hidden)]
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

#[doc(hidden)]
pub fn total_blob_count_for_test(db_path: &Path) -> Result<i64, String> {
    total_blob_count(db_path)
}
