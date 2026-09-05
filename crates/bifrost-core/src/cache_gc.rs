//! Opportunistic GC driver for analyzer rows in the Bifrost cache DB.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Mutex, MutexGuard, OnceLock};

use git2::Repository;
use growable_bloom_filter::GrowableBloom;
use rusqlite::{Connection, TransactionBehavior};

use crate::path_normalization::NormalizePath;
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
    pub analyzer_dropped: usize,
    pub total_blobs_after: i64,
    pub version_stores_removed: usize,
}

impl GcOutcome {
    pub fn skipped(total_blobs_after: i64) -> Self {
        Self {
            ran: false,
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
/// the analyzer store: the registry tables it sweeps are reached through that
/// path rather than through a store handle.
///
/// `workspace_root` is the root of the workspace whose build scheduled this
/// collection. Its files are live by definition, and the Git status scans that
/// seed the live set cannot see files under Git-ignored directories (issue
/// #1963: a workspace rooted inside an ignored subtree), so the sweep retains
/// that workspace's ignored file blobs explicitly.
pub fn maybe_gc(
    db_path: &Path,
    repo: &Repository,
    workspace_root: &Path,
) -> Result<GcOutcome, String> {
    // A deliberately cross-repository cache cannot be collected from the
    // reachability graph of whichever repository happens to open it first.
    // Evaluation and fleet operators that provide such a cache can disable
    // opportunistic collection while retaining the explicit force-GC API.
    if !automatic_gc_enabled(std::env::var_os("BIFROST_CACHE_GC").as_deref()) {
        return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
    }
    run_gc(db_path, repo, workspace_root, false)
}

pub fn force_gc(
    db_path: &Path,
    repo: &Repository,
    workspace_root: &Path,
) -> Result<GcOutcome, String> {
    run_gc(db_path, repo, workspace_root, true)
}

fn run_gc(
    db_path: &Path,
    repo: &Repository,
    workspace_root: &Path,
    force: bool,
) -> Result<GcOutcome, String> {
    let Some(claim) = try_claim_gc(db_path, force)? else {
        return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
    };
    match gitblob::has_network_promisor_remote(repo) {
        Ok(true) => {
            clear_gc_claim(db_path)?;
            eprintln!("Bifrost cache GC skipped: repository uses a network-backed promisor remote");
            return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
        }
        Ok(false) => {}
        Err(error) => {
            clear_gc_claim(db_path)?;
            return Err(format!("cache GC could not inspect Git remotes: {error}"));
        }
    }
    match sweep_with_claim(&claim, repo, workspace_root) {
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

/// How many rows `ANALYZE` may sample per index when refreshing the query
/// planner's statistics.
///
/// SQLite chooses how to run each query -- which index to use, which table to
/// read first -- from statistics it keeps in a table named `sqlite_stat1`.
/// `ANALYZE` is what fills that table in. `PRAGMA analysis_limit = N` caps the
/// per-index sample at about N rows instead of walking every index end to end.
///
/// Measured for issue #3016 on one workspace-built store per supported
/// language (2026-09-04). On the largest, apache/shardingsphere at 244 MB and
/// 86,841 code units, `ANALYZE` cost 1.047 s at this limit against 1.199 s
/// unbounded; on a 137 MB C# store, 0.486 s against 0.596 s. The limit buys
/// little at corpus sizes because the store's indexes are narrow, and it is
/// kept as the bound for stores larger than anything the corpus holds. The
/// full table is in
/// `.agents/plans/issue-3016-analyzer-store-planner-statistics.md`.
pub const PLANNER_ANALYSIS_LIMIT: i64 = 1000;

/// Operator switch for the planner-statistics hooks, alongside
/// `BIFROST_CACHE_GC`. Setting it to `0`, `off`, or `disabled` stops both the
/// post-build and the post-GC refresh, which is how a statistics-free plan is
/// reproduced.
pub const STORE_STATISTICS_ENV: &str = "BIFROST_STORE_STATISTICS";

/// What one planner-statistics refresh did, for the caller to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerStatisticsRefresh {
    pub elapsed: std::time::Duration,
    pub stat1_rows: i64,
}

/// Whether the planner-statistics hooks may run. See [`STORE_STATISTICS_ENV`].
pub fn planner_statistics_enabled() -> bool {
    statistics_enabled(std::env::var_os(STORE_STATISTICS_ENV).as_deref())
}

fn statistics_enabled(value: Option<&OsStr>) -> bool {
    !matches!(
        value.and_then(OsStr::to_str),
        Some("0" | "off" | "disabled")
    )
}

/// Recompute the query planner's statistics for this cache database.
///
/// Reports how long `ANALYZE` took and how many `sqlite_stat1` rows the
/// database carries afterwards, so the caller logs evidence rather than the
/// bare fact that it ran.
pub fn refresh_planner_statistics(conn: &Connection) -> Result<PlannerStatisticsRefresh, String> {
    let started = std::time::Instant::now();
    conn.pragma_update(None, "analysis_limit", PLANNER_ANALYSIS_LIMIT)
        .map_err(|err| format!("planner statistics SQLite error: {err}"))?;
    conn.execute_batch("ANALYZE;")
        .map_err(|err| format!("planner statistics SQLite error: {err}"))?;
    let elapsed = started.elapsed();
    Ok(PlannerStatisticsRefresh {
        elapsed,
        stat1_rows: planner_statistics_row_count(conn)?,
    })
}

/// How many `sqlite_stat1` rows the database carries, or zero when `ANALYZE`
/// has never run: the table does not exist until it does.
pub fn planner_statistics_row_count(conn: &Connection) -> Result<i64, String> {
    let has_table: i64 = conn
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'sqlite_stat1'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|err| format!("planner statistics SQLite error: {err}"))?;
    if has_table == 0 {
        return Ok(0);
    }
    conn.query_row("SELECT count(*) FROM sqlite_stat1", [], |row| row.get(0))
        .map_err(|err| format!("planner statistics SQLite error: {err}"))
}

/// Whether the stored statistics still describe this database.
///
/// The first field of a `sqlite_stat1` row is the table's exact row count at
/// the time `ANALYZE` ran -- `analysis_limit` bounds the per-index sampling,
/// not that total -- so comparing the recorded `blobs` count against the
/// current one answers "has anything been persisted or collected since the
/// last refresh?" exactly, with one indexed query and no new counter. Every
/// persisted blob adds a `blobs` row and every collected blob removes one, so
/// an unchanged count means the statistics are still the ones this store's
/// content produced.
pub fn planner_statistics_describe_database(conn: &Connection) -> Result<bool, String> {
    if planner_statistics_row_count(conn)? == 0 {
        // `ANALYZE` has never run here, or ran when the database held nothing.
        return Ok(false);
    }
    // `ANALYZE` writes no row for an empty table, so a missing `blobs` entry
    // means the last refresh saw no blobs, which is a recorded count of zero.
    let recorded: i64 = conn
        .query_row(
            "SELECT COALESCE(
               (SELECT CAST(substr(stat, 1, instr(stat || ' ', ' ') - 1) AS INTEGER)
                FROM sqlite_stat1
                WHERE tbl = 'blobs' AND idx IS NOT NULL
                LIMIT 1),
               0
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|err| format!("planner statistics SQLite error: {err}"))?;
    Ok(recorded == total_blob_count_conn(conn)?)
}

/// Planner statistics captured from real corpus stores, one workspace build
/// per supported language (issue #3016, 2026-09-04). The file's own header
/// records which stores it came from and how the rows were merged.
///
/// The fixture lives in this crate, not in the analyzer store, because the
/// pinned query plans it has to reproduce are spread across this crate's
/// `cache_db` schema tests, the analyzer store's own tests, and the
/// `suite_persistence` integration suite. One copy is the only way all three
/// plan against the same cardinalities.
#[cfg(any(test, feature = "test-support"))]
const REPRESENTATIVE_SQLITE_STAT1: &str = include_str!("testdata/representative_sqlite_stat1.tsv");

/// The two query-planner states every `EXPLAIN QUERY PLAN` pin in this
/// repository must hold in.
///
/// A plan proved only against a database that has never run `ANALYZE` proves
/// nothing about a repository that has been built, because the build hook
/// leaves statistics behind. `Representative` installs the captured
/// statistics, so the second run plans with cardinalities production has.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannerStatisticsState {
    Absent,
    Representative,
}

#[cfg(any(test, feature = "test-support"))]
impl PlannerStatisticsState {
    /// Both states, in the order a pin should run them.
    pub const BOTH: [Self; 2] = [Self::Absent, Self::Representative];

    /// Put `conn` into this state.
    ///
    /// `Absent` asserts the state it names instead of assuming it, so a pin
    /// cannot quietly run its statistics-free half against a database that
    /// already carries statistics.
    pub fn install(self, conn: &Connection) {
        match self {
            Self::Absent => assert_eq!(
                planner_statistics_row_count(conn).expect("sqlite_stat1 row count"),
                0,
                "the statistics-free half of a plan pin needs a database that has never \
                 run ANALYZE"
            ),
            Self::Representative => with_representative_statistics(conn),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Display for PlannerStatisticsState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Absent => "with no planner statistics",
            Self::Representative => "with representative planner statistics",
        })
    }
}

/// Make `conn`'s query planner read the captured corpus statistics.
///
/// `ANALYZE` on the database creates the `sqlite_stat1` table (empty, when the
/// database holds no rows: `ANALYZE` writes no row for an empty table); the
/// captured rows replace its contents; `ANALYZE sqlite_schema` reloads the
/// planner's cached view of the table without recomputing anything. What the
/// planner reads is `sqlite_stat1`, never the rows themselves, so this
/// reproduces a real store's planning inputs without its data.
///
/// Rows naming a table or index this database does not have are skipped: the
/// capture came from the analyzer store, and the same helper serves the
/// semantic-pack catalog, whose schema shares none of it.
#[cfg(any(test, feature = "test-support"))]
pub fn with_representative_statistics(conn: &Connection) {
    conn.execute_batch("ANALYZE;")
        .expect("ANALYZE creates sqlite_stat1");
    conn.execute("DELETE FROM sqlite_stat1", [])
        .expect("clear sqlite_stat1");
    let mut insert = conn
        .prepare("INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES(?1, ?2, ?3)")
        .expect("prepare sqlite_stat1 insert");
    for line in REPRESENTATIVE_SQLITE_STAT1.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(tbl), Some(idx), Some(stat)) = (fields.next(), fields.next(), fields.next())
        else {
            panic!("captured statistics line is not tab-separated: {line}");
        };
        let idx = if idx.is_empty() { None } else { Some(idx) };
        let known: i64 = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = ?1)",
                [idx.unwrap_or(tbl)],
                |row| row.get(0),
            )
            .expect("schema membership");
        if known == 0 {
            continue;
        }
        insert
            .execute(rusqlite::params![tbl, idx, stat])
            .expect("insert captured statistics");
    }
    drop(insert);
    conn.execute_batch("ANALYZE sqlite_schema;")
        .expect("reload planner statistics");
}

fn sweep_with_claim(
    claim: &GcClaim,
    repo: &Repository,
    workspace_root: &Path,
) -> Result<GcOutcome, String> {
    // Snapshot the rows eligible for this collection before walking Git. A
    // workspace build may persist another blob while the reachability walk is
    // in flight; that new row must belong to the next collection, even when
    // the walk started before its working-tree or ref update became visible.
    let mut conn = cache_db::open_unified_connection(&claim.db_path)?;
    conn.pragma_update(None, "temp_store", "FILE")
        .map_err(|err| format!("cache GC SQLite error: {err}"))?;
    conn.execute_batch(
        "CREATE TEMP TABLE gc_analyzer_candidates(
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

    let live = live_bloom(repo, workspace_root)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
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

    // A collection that removed rows changed the cardinalities the planner
    // reasons from, so the statistics it left behind now describe a database
    // that no longer exists. Refreshing here is what keeps a collected store
    // planning as well as a freshly built one (issue #3016).
    if analyzer_dropped > 0 && planner_statistics_enabled() {
        let evidence = refresh_planner_statistics(&conn)?;
        crate::profiling::note_with(|| {
            format!(
                "cache_gc.planner_statistics refreshed after dropping {analyzer_dropped} rows: \
                 {:.1} ms, {} sqlite_stat1 rows",
                evidence.elapsed.as_secs_f64() * 1000.0,
                evidence.stat1_rows
            )
        });
    }

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

fn live_bloom(repo: &Repository, workspace_root: &Path) -> Result<GrowableBloom, String> {
    let mut live = gitblob::reachable_bloom(repo)?;
    for root in gitblob::worktree_roots(repo)? {
        if let Ok(working_tree) = gitblob::existing_working_tree_oids(&root) {
            for oid in working_tree {
                live.insert(oid);
            }
        }
    }
    for oid in ignored_workspace_file_oids(repo, workspace_root)? {
        live.insert(oid);
    }
    Ok(live)
}

/// Blob OIDs of the scheduling workspace's files that Git ignore rules hide
/// from the status-based working-tree scans above (issue #1963: a workspace
/// rooted inside a Git-ignored subtree, such as an extracted archive under
/// `target/`). The workspace enumeration already walks such a root, so its
/// listing is the authority on which files back an active analysis. Tracked
/// and untracked-but-not-ignored files are already live via the worktree
/// scans, so only ignored files are hashed here.
fn ignored_workspace_file_oids(
    repo: &Repository,
    workspace_root: &Path,
) -> Result<std::collections::HashSet<String>, String> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?
        .canonicalize()
        .map_err(|err| format!("canonicalizing git workdir: {err}"))?
        .normalize();
    let files = crate::analyzer::project::collect_workspace_files(workspace_root)
        .map_err(|err| format!("walking workspace {}: {err}", workspace_root.display()))?;
    let mut out = std::collections::HashSet::new();
    for file in files {
        let abs = file.abs_path();
        let Ok(rel) = abs.strip_prefix(&workdir) else {
            continue;
        };
        if !repo.is_path_ignored(rel).unwrap_or(false) {
            continue;
        }
        // The analyzer identifies a working file by hashing its raw bytes
        // (`Liveness::oids_for_files`), so the retained identity must be the
        // same raw-byte hash.
        if let Ok(oid) = git2::Oid::hash_file(git2::ObjectType::Blob, &abs) {
            out.insert(oid.to_string());
        }
    }
    Ok(out)
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
    conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
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

    /// Issue #1963: a workspace rooted inside a Git-ignored subtree. The
    /// status-based working-tree scans cannot see its files, so the sweep must
    /// retain their blobs through the workspace listing instead of collecting
    /// them as unreachable.
    #[test]
    fn gc_keeps_analyzer_rows_for_ignored_workspace_files() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);
        std::fs::write(repo_root.join(".gitignore"), "/target/\n").unwrap();
        gitblob::test_repo::commit_all(&repo, "ignore build output");

        let workspace_root = repo_root.join("target/extracted");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let source = "package main\n\nfunc main() {}\n";
        std::fs::write(workspace_root.join("main.go"), source).unwrap();
        let live_oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
            .unwrap()
            .to_string();
        let dead_oid = "2222222222222222222222222222222222222222";

        let db_path = gitblob::cache_db_path(&repo_root);
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES('go', 'a', 1)",
                [],
            )
            .unwrap();
            for oid in [live_oid.as_str(), dead_oid] {
                conn.execute(
                    "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'go', 1)",
                    [oid],
                )
                .unwrap();
            }
        }

        let outcome = force_gc(&db_path, &repo, &workspace_root).unwrap();
        assert!(outcome.ran);

        let conn = Connection::open(&db_path).unwrap();
        let remaining: Vec<String> = conn
            .prepare("SELECT blob_oid FROM blobs ORDER BY blob_oid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(remaining, vec![live_oid]);
    }

    #[test]
    fn gc_leaves_orphaned_semantic_cache_rows_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);
        let dead_oid = "2222222222222222222222222222222222222222";
        let vector_hash = [7_u8; 32];

        let db_path = gitblob::cache_db_path(&repo_root);
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES('go', 'a', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'go', 1)",
                [dead_oid],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO semantic_files(blob_oid, rel_path, language)
                 VALUES(?1, 'old.go', 'go')",
                [dead_oid],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO semantic_vectors(vector_hash, dim, vector) VALUES(?1, 1, X'00')",
                [&vector_hash[..]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO semantic_file_chunks(
                   blob_oid, rel_path, chunk_ord, symbol, vector_hash
                 ) VALUES(?1, 'old.go', 0, 'old', ?2)",
                rusqlite::params![dead_oid, &vector_hash[..]],
            )
            .unwrap();
        }

        let outcome = force_gc(&db_path, &repo, &repo_root).unwrap();
        assert!(outcome.ran);
        assert_eq!(outcome.analyzer_dropped, 1);
        assert_eq!(outcome.total_blobs_after, 0);

        let conn = Connection::open(&db_path).unwrap();
        for table in ["semantic_files", "semantic_file_chunks", "semantic_vectors"] {
            let count = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(count, 1, "{table} must remain untouched");
        }
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

    #[test]
    fn gc_skips_network_promisor_repositories_and_releases_its_claim() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);
        std::fs::write(repo_root.join("tracked.txt"), "tracked\n").unwrap();
        gitblob::test_repo::commit_all(&repo, "initial content");
        repo.remote("origin", "https://example.invalid/repo.git")
            .unwrap();
        repo.config()
            .unwrap()
            .set_bool("remote.origin.promisor", true)
            .unwrap();

        let db_path = gitblob::cache_db_path(&repo_root);
        let dead_oid = "3333333333333333333333333333333333333333";
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES('go', 'a', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'go', 1)",
                [dead_oid],
            )
            .unwrap();
        }

        let outcome = force_gc(&db_path, &repo, &repo_root).unwrap();
        assert!(!outcome.ran, "network-backed GC must be skipped");

        let conn = Connection::open(&db_path).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1",
                [dead_oid],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "a skipped sweep retains every candidate"
        );
        assert_eq!(
            conn.query_row(
                "SELECT gc_claim_until FROM cache_state WHERE id = 1",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
            0,
            "the next eligible local sweep must not wait for a stale claim"
        );
    }
}
