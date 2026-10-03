//! Opportunistic GC driver for analyzer rows in the Bifrost cache DB.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

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

const DELETE_ANALYZER_CANDIDATE_SQL: &str = "DELETE FROM blobs
     WHERE blob_oid = ?1 AND lang = ?2 AND generation = ?3
       AND NOT EXISTS (
         SELECT 1
         FROM workspace_file_versions AS versions
           INDEXED BY idx_workspace_file_versions_blob_root
         WHERE versions.input_kind = 'source' AND versions.blob_oid = ?1
           AND versions.lang = ?2
           AND versions.generation = ?3
       )
       AND NOT EXISTS (
         SELECT 1 FROM workspace_resolution_content_roots AS roots
         WHERE roots.blob_id = blobs.id
       )";

// Deterministic test rendezvous after the real candidate snapshot and before
// its deletion transaction. The hook belongs only to its collector test thread.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static RESOLUTION_ROOT_HOOK_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static AFTER_RESOLUTION_ROOT_CANDIDATE_SNAPSHOT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Scoped rendezvous for testing publication between the real GC snapshot and deletion.
#[cfg(any(test, feature = "test-support"))]
pub struct ResolutionRootSnapshotGuard(std::marker::PhantomData<std::rc::Rc<()>>);

#[cfg(any(test, feature = "test-support"))]
impl Drop for ResolutionRootSnapshotGuard {
    fn drop(&mut self) {
        AFTER_RESOLUTION_ROOT_CANDIDATE_SNAPSHOT.with(|hook| {
            hook.borrow_mut().take();
        });
        RESOLUTION_ROOT_HOOK_ACTIVE.with(|active| active.set(false));
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn after_resolution_candidate_snapshot_for_test(
    publish: impl FnOnce() + 'static,
) -> ResolutionRootSnapshotGuard {
    RESOLUTION_ROOT_HOOK_ACTIVE.with(|active| {
        assert!(
            !active.replace(true),
            "nested resolution root snapshot hook"
        );
    });
    AFTER_RESOLUTION_ROOT_CANDIDATE_SNAPSHOT
        .with(|hook| *hook.borrow_mut() = Some(Box::new(publish)));
    ResolutionRootSnapshotGuard(std::marker::PhantomData)
}

#[cfg(test)]
#[path = "cache_gc_resolution_roots_tests.rs"]
mod resolution_roots_tests;

static AUTO_BLOB_THRESHOLD: AtomicI64 = AtomicI64::new(GC_AUTO_BLOB_THRESHOLD);
static MIN_INTERVAL_SECS: AtomicI64 = AtomicI64::new(GC_MIN_INTERVAL_SECS);

/// Serializes complete analyzer-cache reconciliation with garbage collection.
///
/// A build publishes blob facts before it publishes the workspace projection
/// that retains them. Collection must therefore hold this same lock: SQLite
/// transaction boundaries alone cannot distinguish that publication window
/// from an unreachable blob left by a completed build.
#[doc(hidden)]
pub struct AnalyzerCacheBuildLock {
    _file: File,
}

/// How long the wait below sleeps between attempts on a held lock.
const BUILD_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// A wait at least this long is reported to `BIFROST_TIMING`, whether or not
/// it ends in the lock being taken. Below it the wait is ordinary
/// serialization between a build and a collection and says nothing.
const BUILD_LOCK_REPORT_THRESHOLD: Duration = Duration::from_millis(100);

impl AnalyzerCacheBuildLock {
    /// Take the lock, waiting for as long as the current holder needs.
    ///
    /// For a caller with no deadline of its own: a CLI or batch build, or a
    /// forced collection. A caller inside a budgeted request must use
    /// [`Self::acquire_cancellable`] instead, or its wait outlives the budget
    /// and is reported as the budget rather than as the lock (issue #3170).
    pub fn acquire(db_path: &Path) -> Result<Self, String> {
        Self::wait_for_lock(db_path, None)
    }

    /// Take the lock, giving up when the caller's request is cancelled.
    ///
    /// The error names the lock, its path, and how long this caller waited, so
    /// a recurrence is reported as contention on a named lock instead of as an
    /// unattributed timeout. The wait also publishes itself as the request's
    /// phase for as long as it lasts (see
    /// [`CancellationToken::enter_phase`](crate::CancellationToken::enter_phase)).
    pub fn acquire_cancellable(
        db_path: &Path,
        cancellation: &crate::CancellationToken,
    ) -> Result<Self, String> {
        Self::wait_for_lock(db_path, Some(cancellation))
    }

    /// Poll for the lock instead of parking in the kernel on it.
    ///
    /// `std::fs::File::lock` takes no deadline and cannot be interrupted, so a
    /// thread that enters it is unreachable until the holder is done: an MCP
    /// request whose budget expired mid-wait returned a budget error while its
    /// analyzer thread stayed parked. Polling is what makes the wait
    /// answerable to the caller's own cancellation.
    fn wait_for_lock(
        db_path: &Path,
        cancellation: Option<&crate::CancellationToken>,
    ) -> Result<Self, String> {
        let (file, lock_path) = open_build_lock_file(db_path)?;
        let started = std::time::Instant::now();
        // Entered on the first attempt that has to wait, and dropped with this
        // function, so the phase describes exactly the wait.
        let mut phase = None;
        loop {
            match file.try_lock() {
                Ok(()) => {
                    report_build_lock_wait(&lock_path, started.elapsed());
                    return Ok(Self { _file: file });
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(format!(
                        "failed to acquire workspace analyzer build lock {}: {error}",
                        lock_path.display()
                    ));
                }
            }
            if let Some(cancellation) = cancellation {
                if cancellation.is_cancelled() {
                    let waited = started.elapsed();
                    report_build_lock_wait(&lock_path, waited);
                    return Err(format!(
                        "the analyzer cache build lock at {} was held by another builder or \
                         collector for {waited:?}, and this request was cancelled before it \
                         became free",
                        lock_path.display()
                    ));
                }
                if phase.is_none() {
                    phase = Some(cancellation.enter_phase(format!(
                        "waiting for the analyzer cache build lock at {}",
                        lock_path.display()
                    )));
                }
            }
            std::thread::sleep(BUILD_LOCK_POLL_INTERVAL);
        }
    }

    /// Take the lock only if it is free right now.
    ///
    /// `None` means a builder or another collector holds it. Opportunistic
    /// collection uses this: it runs behind interactive work, so waiting for
    /// the lock would put the collection in front of the next request that
    /// needs it, which is the convoy the claim above exists to avoid.
    pub fn try_acquire(db_path: &Path) -> Result<Option<Self>, String> {
        let (file, lock_path) = open_build_lock_file(db_path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => Err(format!(
                "failed to acquire workspace analyzer build lock {}: {error}",
                lock_path.display()
            )),
        }
    }
}

/// Leave a wait for the build lock in the timing log, so a wait that ends is
/// as visible as one that does not.
fn report_build_lock_wait(lock_path: &Path, waited: Duration) {
    if waited < BUILD_LOCK_REPORT_THRESHOLD {
        return;
    }
    crate::profiling::note_with(|| {
        format!(
            "cache_gc.build_lock_wait waited {waited:?} for {}",
            lock_path.display()
        )
    });
}

/// Open the sidecar file the build lock is taken on, reporting its path.
///
/// Keep the established sidecar name so processes running older Bifrost builds
/// coordinate on the same OS lock during an upgrade.
fn open_build_lock_file(db_path: &Path) -> Result<(File, PathBuf), String> {
    let lock_path = analyzer_sidecar_path(db_path, ".initial-build.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| {
            format!(
                "failed to open workspace analyzer build lock {}: {error}",
                lock_path.display()
            )
        })?;
    Ok((file, lock_path))
}

fn analyzer_sidecar_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut path = OsString::from(db_path.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

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
    collection: Collection,
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
    run_gc(db_path, repo, workspace_root, Collection::Opportunistic)
}

pub fn force_gc(
    db_path: &Path,
    repo: &Repository,
    workspace_root: &Path,
) -> Result<GcOutcome, String> {
    run_gc(db_path, repo, workspace_root, Collection::Forced)
}

/// Whether this collection may wait for the other users of the store.
///
/// Opportunistic collection is scheduled behind a build and nobody is waiting
/// for its result, so it must never make a request wait: it takes the build
/// lock only if it is free, its connections carry a short busy timeout, and a
/// store another process is writing is left for the next cadence. A forced
/// collection has an explicit caller waiting for the outcome, so it waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Collection {
    Opportunistic,
    Forced,
}

impl Collection {
    fn open(self, db_path: &Path) -> Result<Connection, String> {
        match self {
            Self::Opportunistic => cache_db::open_collection_connection(db_path),
            Self::Forced => cache_db::open_unified_connection(db_path),
        }
    }

    fn acquire_build_lock(self, db_path: &Path) -> Result<Option<AnalyzerCacheBuildLock>, String> {
        match self {
            Self::Opportunistic => AnalyzerCacheBuildLock::try_acquire(db_path),
            Self::Forced => AnalyzerCacheBuildLock::acquire(db_path).map(Some),
        }
    }
}

/// Why a collection stopped before it collected anything.
///
/// `StoreBusy` is not a failure: another process is building into the store or
/// writing to it, so this collection yields, releases its claim, and leaves
/// the work to the next scheduled one. It is a separate variant rather than a
/// message so the caller can tell the two apart without reading a string.
#[derive(Debug)]
enum GcStopped {
    StoreBusy,
    Failed(String),
}

impl From<rusqlite::Error> for GcStopped {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::StoreBusy
            }
            _ => Self::Failed(format!("cache GC SQLite error: {error}")),
        }
    }
}

impl From<String> for GcStopped {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

fn run_gc(
    db_path: &Path,
    repo: &Repository,
    workspace_root: &Path,
    collection: Collection,
) -> Result<GcOutcome, String> {
    let claim = match claim_gc(db_path, collection) {
        Ok(Some(claim)) => claim,
        Ok(None) | Err(GcStopped::StoreBusy) => {
            return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
        }
        Err(GcStopped::Failed(message)) => return Err(message),
    };
    match gitblob::has_network_promisor_remote(repo) {
        Ok(true) => {
            clear_gc_claim(&claim)?;
            eprintln!("Bifrost cache GC skipped: repository uses a network-backed promisor remote");
            return Ok(GcOutcome::skipped(total_blob_count(db_path)?));
        }
        Ok(false) => {}
        Err(error) => {
            clear_gc_claim(&claim)?;
            return Err(format!("cache GC could not inspect Git remotes: {error}"));
        }
    }
    match sweep_with_claim(&claim, repo, workspace_root) {
        Ok(outcome) => Ok(outcome),
        Err(GcStopped::StoreBusy) => {
            clear_gc_claim(&claim)?;
            Ok(GcOutcome::skipped(total_blob_count(db_path)?))
        }
        Err(GcStopped::Failed(message)) => {
            clear_gc_claim(&claim)?;
            Err(message)
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

/// Serialize tests that change or observe the process-wide planner-statistics
/// switch. The production code intentionally reads the environment directly;
/// tests that temporarily set it must keep other tests from observing the
/// temporary value.
#[cfg(any(test, feature = "test-support"))]
pub fn planner_statistics_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
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
    // ANALYZE can change the chosen plan for every cached statement. Do not
    // let this connection reuse statements prepared against the old stats.
    conn.flush_prepared_statement_cache();
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

/// Whether the stored statistics still describe the current blob cardinality.
/// This is deliberately a staleness proxy: edits that replace one blob with
/// another without changing the count are not detected here.
pub fn planner_statistics_describe_database(conn: &Connection) -> Result<bool, String> {
    if planner_statistics_row_count(conn)? == 0 {
        return Ok(false);
    }
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

/// How many times this process has repaired a store's planner statistics while
/// opening it. Tests observe the repair by this counter rather than by timing.
static PLANNER_STATISTICS_REPAIRS: AtomicI64 = AtomicI64::new(0);

/// Repairs run by [`repair_planner_statistics_on_open`] since the process
/// started.
pub fn planner_statistics_repairs() -> i64 {
    PLANNER_STATISTICS_REPAIRS.load(Ordering::Relaxed)
}

/// Give a built store the statistics it should already have, at open time.
///
/// A store that holds blobs but no statistics is not a slow path, it is a
/// latency cliff: on `laravel/framework` one `most_relevant_files` call took
/// 405 s with `sqlite_stat1` emptied and 3.3 s after one `ANALYZE` of the same
/// file, a factor of 125 (issue #3016's corpus report, finding F3). The build
/// and collection hooks keep a store this build produced current, so the
/// remaining ways into that state are a store built by a binary older than
/// those hooks and a store built while `BIFROST_STORE_STATISTICS=off` was set.
/// Both are repaired here, once, when the database is opened.
///
/// Runs nothing on an empty database -- `ANALYZE` writes no row for an empty
/// table, so an empty store would read as stale forever -- and nothing when
/// [`planner_statistics_describe_database`] says the stored statistics still
/// describe this store.
///
/// `ANALYZE` takes a write transaction, and opening a store deliberately takes
/// no build lock, so this can meet another process mid-build. The connection's
/// 120-second busy timeout is what handles that: the repair waits for the
/// builder's current write transaction, and if the whole timeout expires it
/// reports the SQLite error, the caller leaves the store without statistics,
/// and the next open (or that builder's own post-build hook) does the work.
pub fn repair_planner_statistics_on_open(
    conn: &Connection,
) -> Result<Option<PlannerStatisticsRefresh>, String> {
    if !planner_statistics_enabled() {
        return Ok(None);
    }
    if total_blob_count_conn(conn)? == 0 {
        return Ok(None);
    }
    if planner_statistics_describe_database(conn)? {
        return Ok(None);
    }
    let evidence = refresh_planner_statistics(conn)?;
    PLANNER_STATISTICS_REPAIRS.fetch_add(1, Ordering::Relaxed);
    Ok(Some(evidence))
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
) -> Result<GcOutcome, GcStopped> {
    let mut conn = claim.collection.open(&claim.db_path)?;
    conn.pragma_update(None, "temp_store", "FILE")?;
    conn.execute_batch(
        "CREATE TEMP TABLE gc_analyzer_candidates(
           blob_oid TEXT NOT NULL,
           lang TEXT NOT NULL,
           generation INTEGER NOT NULL,
           PRIMARY KEY(blob_oid, lang, generation)
         ) WITHOUT ROWID;",
    )?;

    // The Git reachability walk reads the repository, not the store, and it is
    // the longest part of a collection. It runs before the build lock is
    // taken, so a request that needs the lock never queues behind it.
    let mut live = live_bloom(repo, workspace_root)?;

    // From here to the deletion commit, and no further.
    //
    // A builder commits a blob's facts before it publishes the workspace
    // projection that retains them, and holds this lock across both. The lock
    // is therefore what makes "this blob has no root" a question with an
    // answer: under it, no build is mid-reconciliation, so every committed
    // blob either belongs to a published projection or belongs to none.
    //
    // That is also why the Git walk above may run outside it. A builder that
    // published after the walk but before this point is covered by the
    // `workspace_file_versions` roots read below, inside the deletion
    // transaction; a blob committed after the candidate snapshot is not a
    // candidate at all. What the lock must cover is the pair -- the snapshot
    // and the roots read -- not the walk that seeds them.
    //
    // The vacuum, the planner-statistics refresh, the accounting update and
    // the version-store sweep all run after it is released: none of them can
    // reclaim a row, so none of them needs to exclude a builder.
    let Some(build_lock) = claim.collection.acquire_build_lock(&claim.db_path)? else {
        return Err(GcStopped::StoreBusy);
    };

    // Snapshot the rows eligible for this collection. A workspace build may
    // persist another blob once the lock is released; that new row belongs to
    // the next collection.
    conn.execute_batch(
        "INSERT INTO gc_analyzer_candidates(blob_oid, lang, generation)
           SELECT blobs.blob_oid, blobs.lang, blobs.generation
           FROM blobs
           LEFT JOIN analysis_epochs AS epochs ON epochs.lang = blobs.lang
           WHERE blobs.generation = COALESCE(epochs.generation, 0);",
    )?;

    #[cfg(any(test, feature = "test-support"))]
    AFTER_RESOLUTION_ROOT_CANDIDATE_SNAPSHOT.with(|hook| {
        let publish = hook.borrow_mut().take();
        if let Some(publish) = publish {
            publish();
        }
    });
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Retained workspace revisions also own their blobs, including immutable
    // diff images whose objects need not be reachable from any Git ref. Read
    // these roots under the deletion transaction so a projection published
    // during the Git walk is protected too. Stream them once rather than
    // scanning workspace history separately for every candidate blob.
    {
        let mut stmt =
            tx.prepare("SELECT blob_oid FROM workspace_file_versions WHERE input_kind = 'source'")?;
        let roots = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for root in roots {
            live.insert(root?);
        }
    }
    let dead_analyzer = {
        let mut stmt =
            tx.prepare("SELECT blob_oid, lang, generation FROM gc_analyzer_candidates")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|(oid, _, _)| !live.contains(oid))
            .collect::<Vec<_>>()
    };
    let analyzer_dropped = delete_analyzer_candidates(&tx, &dead_analyzer)?;
    tx.commit()?;
    drop(build_lock);

    // This collection is done; what follows is maintenance on the store it has
    // already changed, and every part of it has a next chance -- the pages
    // this one freed are returned by the next collection's vacuum, and a store
    // whose statistics no longer describe it is repaired the next time it is
    // opened (#3031). A store the live session is writing therefore postpones
    // the maintenance instead of turning a collection that happened into one
    // reported as skipped: that report is what tells the caller to recycle the
    // readers whose query plans the deletions invalidated (#3029).
    let total_blobs_after = match maintain_collected_store(&mut conn, analyzer_dropped) {
        Ok(total) => total,
        Err(GcStopped::StoreBusy) => {
            eprintln!(
                "Bifrost cache GC collected {analyzer_dropped} rows and left its bookkeeping to \
                 the next collection: another writer holds the store"
            );
            total_blob_count_conn(&conn)?
        }
        Err(failed) => return Err(failed),
    };
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

/// Return the freed pages, refresh the statistics the deletions invalidated,
/// and record the collection in `cache_state`. Reports the store's blob count
/// afterwards.
///
/// Runs on the sweep's own connection, with the build lock already released:
/// none of this can reclaim a row, so none of it needs to exclude a builder.
fn maintain_collected_store(
    conn: &mut Connection,
    analyzer_dropped: usize,
) -> Result<i64, GcStopped> {
    cache_db::drain_free_pages(conn)?;

    // A collection that removed rows changed the cardinalities the planner
    // reasons from, so the statistics it left behind now describe a database
    // that no longer exists. Refreshing here is what keeps a collected store
    // planning as well as a freshly built one (issue #3016).
    if analyzer_dropped > 0 && planner_statistics_enabled() {
        let evidence = refresh_planner_statistics(conn)?;
        crate::profiling::note_with(|| {
            format!(
                "cache_gc.planner_statistics refreshed after dropping {analyzer_dropped} rows: \
                 {:.1} ms, {} sqlite_stat1 rows",
                evidence.elapsed.as_secs_f64() * 1000.0,
                evidence.stat1_rows
            )
        });
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let total = total_blob_count_conn(&tx)?;
    tx.execute(
        "UPDATE cache_state
         SET last_gc_at = ?1, blobs_at_last_gc = ?2, gc_claim_until = 0
         WHERE id = 1",
        (cache_db::now_unix_seconds(), total),
    )?;
    tx.commit()?;
    cache_db::drain_free_pages(conn)?;
    Ok(total)
}

fn delete_analyzer_candidates(
    tx: &rusqlite::Transaction<'_>,
    candidates: &[(String, String, i64)],
) -> Result<usize, GcStopped> {
    let mut delete = tx.prepare(DELETE_ANALYZER_CANDIDATE_SQL)?;
    let mut dropped = 0usize;
    for (oid, lang, generation) in candidates {
        dropped += delete.execute((oid, lang, generation))?;
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

fn claim_gc(db_path: &Path, collection: Collection) -> Result<Option<GcClaim>, GcStopped> {
    let mut conn = collection.open(db_path)?;
    let now = cache_db::now_unix_seconds();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current_total = total_blob_count_conn(&tx)?;
    let claim_until: i64 = tx.query_row(
        "SELECT gc_claim_until FROM cache_state WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    if claim_until > now {
        tx.commit()?;
        return Ok(None);
    }
    if collection == Collection::Opportunistic && !gc_due_tx(&tx, current_total, now)? {
        tx.commit()?;
        return Ok(None);
    }
    tx.execute(
        "UPDATE cache_state SET gc_claim_until = ?1 WHERE id = 1",
        [now + GC_CLAIM_TTL_SECS],
    )?;
    tx.commit()?;
    Ok(Some(GcClaim {
        db_path: db_path.to_path_buf(),
        collection,
    }))
}

fn gc_due_tx(
    tx: &rusqlite::Transaction<'_>,
    current_total: i64,
    now: i64,
) -> Result<bool, GcStopped> {
    let (last_gc_at, blobs_at_last_gc): (i64, i64) = tx.query_row(
        "SELECT last_gc_at, blobs_at_last_gc FROM cache_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let growth = current_total - blobs_at_last_gc;
    if growth <= 0 {
        return Ok(false);
    }
    if growth > AUTO_BLOB_THRESHOLD.load(Ordering::Relaxed) {
        return Ok(true);
    }
    Ok(now.saturating_sub(last_gc_at) >= MIN_INTERVAL_SECS.load(Ordering::Relaxed))
}

fn clear_gc_claim(claim: &GcClaim) -> Result<(), String> {
    let mut conn = claim.collection.open(&claim.db_path)?;
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

    #[test]
    fn planner_statistics_refresh_tracks_blob_cardinality() {
        let mut conn = Connection::open_in_memory().unwrap();
        cache_db::configure_connection(&mut conn).unwrap();
        cache_db::migrate(&mut conn).unwrap();
        conn.execute_batch("DROP TABLE IF EXISTS sqlite_stat1;")
            .unwrap();
        assert_eq!(planner_statistics_row_count(&conn).unwrap(), 0);
        assert!(!planner_statistics_describe_database(&conn).unwrap());

        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation)
             VALUES('1111111111111111111111111111111111111111', 'rust', 0)",
            [],
        )
        .unwrap();
        let evidence = refresh_planner_statistics(&conn).unwrap();
        assert_eq!(
            conn.pragma_query_value(None, "analysis_limit", |row| row.get::<_, i64>(0))
                .unwrap(),
            PLANNER_ANALYSIS_LIMIT
        );
        assert_eq!(
            evidence.stat1_rows,
            planner_statistics_row_count(&conn).unwrap()
        );
        assert!(evidence.stat1_rows > 0);
        assert!(planner_statistics_describe_database(&conn).unwrap());

        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation)
             VALUES('2222222222222222222222222222222222222222', 'rust', 0)",
            [],
        )
        .unwrap();
        assert!(!planner_statistics_describe_database(&conn).unwrap());
        let repaired = repair_planner_statistics_on_open(&conn).unwrap();
        assert!(repaired.is_some());
        assert!(planner_statistics_describe_database(&conn).unwrap());
    }

    #[test]
    fn planner_statistics_switch_recognizes_disabled_values() {
        assert!(statistics_enabled(None));
        assert!(statistics_enabled(Some(OsStr::new("on"))));
        assert!(!statistics_enabled(Some(OsStr::new("0"))));
        assert!(!statistics_enabled(Some(OsStr::new("off"))));
        assert!(!statistics_enabled(Some(OsStr::new("disabled"))));
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

    /// One blob row and an analysis epoch: the smallest store a collection has
    /// a reason to sweep.
    fn store_with_one_collectable_blob(repo_root: &Path) -> PathBuf {
        let db_path = gitblob::cache_db_path(repo_root);
        let conn = cache_db::open_unified_connection(&db_path).unwrap();
        conn.execute(
            "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES('go', 'a', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation)
             VALUES('2222222222222222222222222222222222222222', 'go', 1)",
            [],
        )
        .unwrap();
        db_path
    }

    fn gc_claim_until(db_path: &Path) -> i64 {
        Connection::open(db_path)
            .unwrap()
            .query_row(
                "SELECT gc_claim_until FROM cache_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Issue #3170: opportunistic collection yields to a builder rather than
    /// queueing in front of the requests waiting on the same lock.
    #[test]
    fn opportunistic_gc_skips_while_a_builder_holds_the_lock() {
        let _tuning = set_tuning_for_test(GC_AUTO_BLOB_THRESHOLD, 0);
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);
        let db_path = store_with_one_collectable_blob(&repo_root);

        let build_lock = AnalyzerCacheBuildLock::acquire(&db_path).unwrap();
        let started = std::time::Instant::now();
        let outcome = maybe_gc(&db_path, &repo, &repo_root).unwrap();
        let elapsed = started.elapsed();
        drop(build_lock);

        assert!(
            !outcome.ran,
            "a collection must not sweep a store a builder is still publishing into: {outcome:?}"
        );
        assert_eq!(
            outcome.total_blobs_after, 1,
            "a skipped collection retains every candidate"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "the collection waited {elapsed:?} for a lock it must not wait for"
        );
        assert_eq!(
            gc_claim_until(&db_path),
            0,
            "the next eligible collection must not wait out a stale claim"
        );
    }

    /// Issue #3170: the live session's writer is what a collection meets in
    /// practice -- an index warm queued after the previous tool call. The
    /// store's 120-second busy timeout is twice the MCP request budget, so an
    /// opportunistic collection that inherited it would outlast the request it
    /// is blocking. It uses its own short timeout and skips instead.
    #[test]
    fn opportunistic_gc_skips_a_store_another_writer_holds() {
        let _tuning = set_tuning_for_test(GC_AUTO_BLOB_THRESHOLD, 0);
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);
        let db_path = store_with_one_collectable_blob(&repo_root);

        let mut writer = cache_db::open_unified_connection(&db_path).unwrap();
        let held = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let started = std::time::Instant::now();
        let outcome = maybe_gc(&db_path, &repo, &repo_root).unwrap();
        let elapsed = started.elapsed();
        held.rollback().unwrap();

        assert!(
            !outcome.ran,
            "a collection must yield the write lock to the live session: {outcome:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(60),
            "the collection waited {elapsed:?}, which is the store's writer timeout rather than \
             the collection's own"
        );
    }

    /// A persisted build commits blob facts before its workspace projection.
    /// Collection may claim work during that interval, but it must not inspect
    /// candidates until the build publishes the projection and releases the
    /// shared lock.
    #[test]
    fn gc_waits_for_complete_analyzer_cache_reconciliation() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let _repo = gitblob::test_repo::init_repo(&repo_root);
        let db_path = gitblob::cache_db_path(&repo_root);
        let unpublished_oid = "2222222222222222222222222222222222222222";
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES('go', 'a', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'go', 1)",
                [unpublished_oid],
            )
            .unwrap();
        }

        let build_lock = AnalyzerCacheBuildLock::acquire(&db_path).unwrap();
        let gc_root = repo_root.clone();
        let gc_db = db_path.clone();
        let gc = std::thread::spawn(move || {
            let repo = Repository::open(&gc_root).unwrap();
            force_gc(&gc_db, &repo, &gc_root)
        });

        let conn = Connection::open(&db_path).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let claim_until: i64 = conn
                .query_row(
                    "SELECT gc_claim_until FROM cache_state WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            if claim_until > 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "collection never claimed the deterministic build-overlap fixture"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1",
                [unpublished_oid],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "collection must not inspect facts from an incomplete build"
        );

        drop(build_lock);
        let outcome = gc.join().unwrap().unwrap();
        assert_eq!(outcome.analyzer_dropped, 1);
    }

    /// A collection has to return every page its deletes freed, not one page.
    /// `PRAGMA incremental_vacuum` emits a result row per page it moves, so a
    /// caller that steps it once frees one page and leaves the rest of the
    /// freelist in the file. This fixture deletes enough rows to free far more
    /// than the two pages the two pragma calls in a collection used to reclaim,
    /// which is what makes the assertion fail against that code.
    #[test]
    fn collection_returns_every_freed_page_to_the_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);

        let db_path = gitblob::cache_db_path(&repo_root);
        let filler = "x".repeat(4096);
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES('go', 'a', 1)",
                [],
            )
            .unwrap();
            conn.execute_batch("BEGIN").unwrap();
            for index in 0..200 {
                conn.execute(
                    "INSERT INTO blobs(blob_oid, lang, generation)
                     VALUES(printf('%040x', ?1), 'go', 1)",
                    [index],
                )
                .unwrap();
                let blob_id = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO blob_meta(
                       blob_id, lang, contains_tests, content_package,
                       stored_unit_count, range_count, signature_count,
                       signature_metadata_count, supertype_count, child_count,
                       import_statement_count, type_identifier_count, is_complete
                     ) VALUES(?1, 'go', 0, ?2, 0, 0, 0, 0, 0, 0, 0, 0, 1)",
                    rusqlite::params![blob_id, filler],
                )
                .unwrap();
            }
            conn.execute_batch("COMMIT").unwrap();
            cache_db::checkpoint_wal_for_close(&conn).unwrap();
        }
        let pages_before: i64 = Connection::open(&db_path)
            .unwrap()
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap();

        let outcome = force_gc(&db_path, &repo, &repo_root).unwrap();
        assert_eq!(outcome.analyzer_dropped, 200);

        let conn = cache_db::open_unified_connection(&db_path).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA freelist_count", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0,
            "a collection must leave no page on the freelist"
        );
        let pages_after: i64 = conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap();
        assert!(
            pages_after < pages_before,
            "the file must shrink: {pages_before} -> {pages_after} pages"
        );
    }

    #[test]
    fn forced_gc_keeps_blob_reachable_only_from_retained_workspace_revision() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);
        let retained_oid = "4444444444444444444444444444444444444444";
        let workspace_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let projection_digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let db_path = gitblob::cache_db_path(&repo_root);
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation)
                 VALUES('java', 'active', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation)
                 VALUES(?1, 'java', 1)",
                [retained_oid],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', 1, 1)",
                [workspace_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from, valid_until
                 ) VALUES(?1, 'java', 1, 'src/Retained.java', ?2, ?3, 1, 2)",
                rusqlite::params![workspace_id, retained_oid, projection_digest],
            )
            .unwrap();
        }

        let outcome = force_gc(&db_path, &repo, &repo_root).unwrap();
        assert!(outcome.ran);
        assert_eq!(outcome.analyzer_dropped, 0);

        let conn = Connection::open(&db_path).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                [retained_oid],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
    }

    /// R5.3: a sealed resolution interior is reclaimed by collecting the blob
    /// that owns it, and nothing else. While a retained workspace revision
    /// still names the blob the whole interior stays; once that revision is
    /// retired the next collection drops the blob and its foreign keys take
    /// the interior and every family hanging off it.
    #[test]
    fn forced_gc_reclaims_sealed_resolution_interiors_once_the_revision_retires() {
        let temp = tempfile::tempdir().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&repo_root);
        let oid = "5555555555555555555555555555555555555555";
        let workspace_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let projection_digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let interior_tables = [
            "resolution_fragment_interiors",
            "resolution_reference_lookup_identities",
        ];

        let db_path = gitblob::cache_db_path(&repo_root);
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation)
                 VALUES('java', 'active', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 1)",
                [oid],
            )
            .unwrap();
            let blob_id: i64 = conn
                .query_row(
                    "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                    [oid],
                    |row| row.get(0),
                )
                .unwrap();
            conn.execute(
                "INSERT INTO blob_meta(
                   blob_id, lang, contains_tests, content_package,
                   stored_unit_count, range_count, signature_count,
                   signature_metadata_count, supertype_count, child_count,
                   import_statement_count, type_identifier_count, is_complete
                 ) VALUES(?1, 'java', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1)",
                [blob_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, expected_reference_lookup_identity_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'java', 'java', 'resolution-v1', zeroblob(32), 0, 2, 4, 64, 'building')",
                [blob_id],
            )
            .unwrap();
            for semantic_key in [0, 1] {
                conn.execute(
                    "INSERT INTO resolution_identities(id, identity_digest)
                     VALUES(?1, randomblob(32))",
                    [semantic_key + 1],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO resolution_reference_lookup_identities(
                       blob_id, semantic_key, identity_id
                     ) VALUES(?1, ?2, ?3)",
                    rusqlite::params![blob_id, semantic_key, semantic_key + 1],
                )
                .unwrap();
            }
            conn.execute(
                "UPDATE resolution_fragment_interiors
                 SET publication_state = 'complete' WHERE blob_id = ?1",
                [blob_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', 1, 1)",
                [workspace_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from, valid_until
                 ) VALUES(?1, 'java', 1, 'src/Retained.java', ?2, ?3, 1, 2)",
                rusqlite::params![workspace_id, oid, projection_digest],
            )
            .unwrap();
        }

        let pinned = force_gc(&db_path, &repo, &repo_root).unwrap();
        assert!(pinned.ran);
        assert_eq!(
            pinned.analyzer_dropped, 0,
            "a retained revision still pins the blob"
        );
        {
            let conn = Connection::open(&db_path).unwrap();
            for table in interior_tables {
                assert!(
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                        .unwrap()
                        > 0,
                    "{table} must survive while the revision is retained"
                );
            }
            // Retiring the revision cascades its file versions, so nothing
            // roots the blob any longer.
            conn.execute(
                "DELETE FROM workspace_revisions WHERE workspace_id = ?1",
                [workspace_id],
            )
            .unwrap();
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM workspace_file_versions", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
                0
            );
        }

        let retired = force_gc(&db_path, &repo, &repo_root).unwrap();
        assert!(retired.ran);
        assert_eq!(retired.analyzer_dropped, 1);
        assert_eq!(retired.total_blobs_after, 0);

        let conn = Connection::open(&db_path).unwrap();
        for table in interior_tables {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0,
                "the blob cascade must reclaim {table}"
            );
        }
        let violations: Vec<String> = conn
            .prepare("SELECT \"table\" FROM pragma_foreign_key_check")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            violations.is_empty(),
            "a reclaimed interior must leave no dangling rows: {violations:?}"
        );
    }

    /// Operator measurement for R5.3: how many bytes a collection returns to a
    /// populated store without `VACUUM`, and how long it takes.
    ///
    /// Two collections run against one copy. The first keeps the store's
    /// retained workspace revisions, which root every blob they name; the
    /// second runs after those revisions are retired, which is the state a
    /// reclaim actually happens in. Reporting both is what distinguishes "the
    /// sweep found nothing" from "the sweep cannot reclaim".
    ///
    /// `BIFROST_R53_STORE_PATH` names a populated `bifrost_cache.v117.db`. The
    /// store is copied into a temporary directory first, so this measurement
    /// can never collect the named store itself.
    ///
    /// `BIFROST_R53_REPO_PATH` names the repository whose reachability drives
    /// the sweep. Without it the sweep runs against an empty repository, which
    /// makes every analyzer blob unreachable.
    #[test]
    #[ignore = "operator measurement: needs a populated store"]
    fn measure_reclaim_on_a_disposable_store_copy() {
        let source = std::path::PathBuf::from(
            std::env::var("BIFROST_R53_STORE_PATH").expect("BIFROST_R53_STORE_PATH"),
        );
        let empty_repo = tempfile::tempdir().unwrap();
        let repo = match std::env::var("BIFROST_R53_REPO_PATH") {
            Ok(path) => Repository::discover(path).expect("open the reachability repository"),
            Err(_) => gitblob::test_repo::init_repo(empty_repo.path()),
        };
        let workspace_root = repo
            .workdir()
            .expect("the repository needs a working tree")
            .to_path_buf();

        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(cache_db::cache_db_file_name());
        std::fs::copy(&source, &db_path).expect("copy the store");
        // A copied store may carry an unapplied WAL; checkpoint it into the
        // copy so the before-size is the size of the data being collected.
        for suffix in ["-wal", "-shm"] {
            let sidecar = source.with_file_name(format!(
                "{}{suffix}",
                source.file_name().unwrap().to_string_lossy()
            ));
            if sidecar.exists() {
                std::fs::copy(
                    &sidecar,
                    db_path.with_file_name(format!(
                        "{}{suffix}",
                        db_path.file_name().unwrap().to_string_lossy()
                    )),
                )
                .expect("copy the store sidecar");
            }
        }
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("checkpoint the copy");
        }

        let checkpointed_bytes = |path: &std::path::Path| {
            let conn = cache_db::open_unified_connection(path).unwrap();
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("checkpoint the store");
            drop(conn);
            std::fs::metadata(path).unwrap().len()
        };
        let collect = |label: &str| {
            let bytes_before = checkpointed_bytes(&db_path);
            let blobs_before = total_blob_count(&db_path).unwrap();
            let started = std::time::Instant::now();
            let outcome = force_gc(&db_path, &repo, &workspace_root).unwrap();
            let elapsed = started.elapsed();
            let bytes_after = checkpointed_bytes(&db_path);
            println!(
                "R5.3 reclaim [{label}]: ran={} blobs {} -> {} (dropped {}), \
                 bytes {} -> {} (freed {}), version stores removed {}, {:.3} s",
                outcome.ran,
                blobs_before,
                outcome.total_blobs_after,
                outcome.analyzer_dropped,
                bytes_before,
                bytes_after,
                bytes_before.saturating_sub(bytes_after),
                outcome.version_stores_removed,
                elapsed.as_secs_f64(),
            );
            assert!(outcome.ran, "the {label} collection must run");
            assert!(
                bytes_after <= bytes_before,
                "the {label} collection must not grow the store: \
                 {bytes_before} -> {bytes_after}"
            );
            outcome
        };

        let retained = collect("revisions retained");
        {
            let conn = cache_db::open_unified_connection(&db_path).unwrap();
            // `workspace_heads` names its revision through a foreign key with
            // no delete action, so retiring a revision starts by dropping the
            // head that points at it.
            conn.execute("DELETE FROM workspace_heads", [])
                .expect("drop the workspace heads");
            let revisions = conn
                .execute("DELETE FROM workspace_revisions", [])
                .expect("retire the workspace revisions");
            let versions: i64 = conn
                .query_row("SELECT COUNT(*) FROM workspace_file_versions", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(
                versions, 0,
                "retiring a revision cascades its file versions"
            );
            println!("R5.3 reclaim: retired {revisions} workspace revisions");
        }
        let retired = collect("revisions retired");
        assert!(
            retired.analyzer_dropped >= retained.analyzer_dropped,
            "retiring revisions cannot protect blobs it used to root"
        );
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
    fn analyzer_gc_candidate_cannot_delete_blob_rooted_only_by_retained_revision() {
        let mut conn = Connection::open_in_memory().unwrap();
        cache_db::configure_connection(&mut conn).unwrap();
        cache_db::migrate(&mut conn).unwrap();
        let oid = "2222222222222222222222222222222222222222";
        let workspace_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let projection_digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        conn.execute(
            "INSERT INTO analysis_epochs(lang, epoch, generation)
             VALUES('java', 'active', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 1)",
            [oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, 'java', 1, 1)",
            [workspace_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspace_file_versions(
               workspace_id, lang, generation, rel_path, blob_oid,
               projection_digest, valid_from, valid_until
             ) VALUES(?1, 'java', 1, 'src/Retained.java', ?2, ?3, 1, 2)",
            rusqlite::params![workspace_id, oid, projection_digest],
        )
        .unwrap();

        let candidate = vec![(oid.to_string(), "java".to_string(), 1)];
        let tx = conn.transaction().unwrap();
        assert_eq!(delete_analyzer_candidates(&tx, &candidate).unwrap(), 0);
        tx.commit().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                [oid],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "closed file-version intervals still root retained revisions"
        );
    }

    #[test]
    fn retained_revision_root_probe_uses_the_blob_identity_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        cache_db::configure_connection(&mut conn).unwrap();
        cache_db::migrate(&mut conn).unwrap();
        let details = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {DELETE_ANALYZER_CANDIDATE_SQL}"
            ))
            .unwrap()
            .query_map(
                rusqlite::params!["2222222222222222222222222222222222222222", "java", 1],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            details.iter().any(|detail| {
                detail.contains(
                    "SEARCH versions USING COVERING INDEX idx_workspace_file_versions_blob_root",
                )
            }),
            "retained-revision roots must be point-probed by blob identity: {details:?}"
        );
        assert!(
            details
                .iter()
                .all(|detail| !detail.contains("SCAN versions")),
            "retained-revision root checks must not scan file-version history: {details:?}"
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
