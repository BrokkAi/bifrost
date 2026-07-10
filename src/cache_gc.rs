//! Shared semantic-cache GC for the unified Bifrost cache database.
//!
//! Claim/throttle and Git liveness are shared plumbing. Issue #584 does not
//! create or sweep analyzer rows.

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};

use git2::Repository;
use growable_bloom_filter::GrowableBloom;
use rusqlite::{Connection, TransactionBehavior};

use crate::nlp::store::SemanticStore;
use crate::{cache_db, gitblob};

pub(crate) const GC_AUTO_BLOB_THRESHOLD: i64 = 5000;
pub(crate) const GC_MIN_INTERVAL_SECS: i64 = 6 * 3600;
const GC_CLAIM_TTL_SECS: i64 = 3600;

static AUTO_BLOB_THRESHOLD: AtomicI64 = AtomicI64::new(GC_AUTO_BLOB_THRESHOLD);
static MIN_INTERVAL_SECS: AtomicI64 = AtomicI64::new(GC_MIN_INTERVAL_SECS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GcOutcome {
    pub(crate) ran: bool,
    pub(crate) semantic_dropped: usize,
    pub(crate) total_blobs_after: i64,
}

impl GcOutcome {
    fn skipped(total_blobs_after: i64) -> Self {
        Self {
            ran: false,
            semantic_dropped: 0,
            total_blobs_after,
        }
    }
}

struct GcClaim {
    db_path: std::path::PathBuf,
}

pub(crate) fn maybe_gc_for_semantic(
    store: &SemanticStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    run_gc(store.db_path(), repo, false)
}

pub(crate) fn force_gc_for_semantic(
    store: &SemanticStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    run_gc(store.db_path(), repo, true)
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

fn sweep_with_claim(claim: &GcClaim, repo: &Repository) -> Result<GcOutcome, String> {
    let live = live_bloom(repo)?;
    // A dedicated connection keeps background GC off the foreground store mutex.
    let semantic = SemanticStore::open(&claim.db_path).map_err(|err| err.to_string())?;
    let semantic_dropped = semantic
        .gc_with(|oid| live.contains(oid))
        .map_err(|err| err.to_string())?;
    let total_blobs_after = finish_gc(&claim.db_path)?;
    Ok(GcOutcome {
        ran: true,
        semantic_dropped,
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
        .map_err(gc_sqlite_error)?;
    let current_total = total_blob_count_conn(&tx)?;
    let claim_until: i64 = tx
        .query_row(
            "SELECT gc_claim_until FROM cache_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(gc_sqlite_error)?;
    if claim_until > now {
        tx.commit().map_err(gc_sqlite_error)?;
        return Ok(None);
    }
    if !force && !gc_due_tx(&tx, current_total, now)? {
        tx.commit().map_err(gc_sqlite_error)?;
        return Ok(None);
    }
    tx.execute(
        "UPDATE cache_state SET gc_claim_until = ?1 WHERE id = 1",
        [now + GC_CLAIM_TTL_SECS],
    )
    .map_err(gc_sqlite_error)?;
    tx.commit().map_err(gc_sqlite_error)?;
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
        .map_err(gc_sqlite_error)?;
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
        .map_err(gc_sqlite_error)?;
    let total = total_blob_count_conn(&tx)?;
    let now = cache_db::now_unix_seconds();
    tx.execute(
        "UPDATE cache_state
         SET last_gc_at = ?1, blobs_at_last_gc = ?2, gc_claim_until = 0
         WHERE id = 1",
        (now, total),
    )
    .map_err(gc_sqlite_error)?;
    tx.commit().map_err(gc_sqlite_error)?;
    conn.pragma_update(None, "incremental_vacuum", 0)
        .map_err(gc_sqlite_error)?;
    Ok(total)
}

fn clear_gc_claim(db_path: &Path) -> Result<(), String> {
    let mut conn = cache_db::open_unified_connection(db_path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(gc_sqlite_error)?;
    tx.execute("UPDATE cache_state SET gc_claim_until = 0 WHERE id = 1", [])
        .map_err(gc_sqlite_error)?;
    tx.commit().map_err(gc_sqlite_error)?;
    Ok(())
}

fn total_blob_count(db_path: &Path) -> Result<i64, String> {
    let conn = cache_db::open_unified_connection(db_path)?;
    total_blob_count_conn(&conn)
}

fn total_blob_count_conn(conn: &Connection) -> Result<i64, String> {
    conn.query_row("SELECT COUNT(*) FROM semantic_blobs", [], |row| row.get(0))
        .map_err(gc_sqlite_error)
}

fn gc_sqlite_error(err: rusqlite::Error) -> String {
    format!("cache GC SQLite error: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitblob::tests::{commit_all, init_repo};
    use git2::{ObjectType, Oid};
    use std::sync::{Mutex, OnceLock};

    struct TuningGuard {
        previous_threshold: i64,
        previous_interval: i64,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for TuningGuard {
        fn drop(&mut self) {
            AUTO_BLOB_THRESHOLD.store(self.previous_threshold, Ordering::Relaxed);
            MIN_INTERVAL_SECS.store(self.previous_interval, Ordering::Relaxed);
        }
    }

    fn set_tuning(auto_threshold: i64, min_interval_secs: i64) -> TuningGuard {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("GC tuning test mutex poisoned");
        TuningGuard {
            previous_threshold: AUTO_BLOB_THRESHOLD.swap(auto_threshold, Ordering::Relaxed),
            previous_interval: MIN_INTERVAL_SECS.swap(min_interval_secs, Ordering::Relaxed),
            _lock: lock,
        }
    }

    fn put_oid(store: &SemanticStore, oid: Oid) {
        store.put_blob(&oid.to_string(), None, &[]).unwrap();
    }

    fn is_present(store: &SemanticStore, oid: Oid) -> bool {
        store.missing_blobs(&[oid.to_string()]).unwrap().is_empty()
    }

    #[test]
    fn forced_gc_preserves_detached_worktree_head_and_dirty_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let repo = init_repo(&root);
        std::fs::write(root.join("tracked.txt"), b"base\n").unwrap();
        commit_all(&repo, "base");

        let linked = temp.path().join("linked");
        let output = std::process::Command::new("git")
            .current_dir(&root)
            .args([
                "worktree",
                "add",
                "--detach",
                linked.to_str().unwrap(),
                "HEAD",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let linked_repo = Repository::open(&linked).unwrap();
        std::fs::write(linked.join("tracked.txt"), b"detached\n").unwrap();
        commit_all(&linked_repo, "detached");
        let detached_oid = Oid::hash_object(ObjectType::Blob, b"detached\n").unwrap();
        std::fs::write(linked.join("tracked.txt"), b"dirty\n").unwrap();
        let dirty_oid = Oid::hash_object(ObjectType::Blob, b"dirty\n").unwrap();
        let unreachable_oid = Oid::hash_object(ObjectType::Blob, b"unreachable\n").unwrap();

        let db_path = gitblob::cache_db_path(&root);
        let store = SemanticStore::open(&db_path).unwrap();
        put_oid(&store, detached_oid);
        put_oid(&store, dirty_oid);
        put_oid(&store, unreachable_oid);

        let outcome = force_gc_for_semantic(&store, &repo).unwrap();
        assert!(outcome.ran);
        assert_eq!(outcome.semantic_dropped, 1);
        assert_eq!(outcome.total_blobs_after, 2);
        assert!(is_present(&store, detached_oid));
        assert!(is_present(&store, dirty_oid));
        assert!(!is_present(&store, unreachable_oid));
    }

    #[test]
    fn opportunistic_gc_uses_growth_threshold_and_interval() {
        let _tuning = set_tuning(1, 24 * 3600);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let repo = init_repo(&root);
        let db_path = gitblob::cache_db_path(&root);
        let store = SemanticStore::open(&db_path).unwrap();
        let conn = cache_db::open_unified_connection(&db_path).unwrap();
        conn.execute(
            "UPDATE cache_state
             SET last_gc_at = ?1, blobs_at_last_gc = 0, gc_claim_until = 0
             WHERE id = 1",
            [cache_db::now_unix_seconds()],
        )
        .unwrap();

        put_oid(&store, Oid::hash_object(ObjectType::Blob, b"one").unwrap());
        let skipped = maybe_gc_for_semantic(&store, &repo).unwrap();
        assert!(!skipped.ran);
        put_oid(&store, Oid::hash_object(ObjectType::Blob, b"two").unwrap());
        let swept = maybe_gc_for_semantic(&store, &repo).unwrap();
        assert!(swept.ran);
        assert_eq!(swept.semantic_dropped, 2);
        assert_eq!(swept.total_blobs_after, 0);
    }
}
