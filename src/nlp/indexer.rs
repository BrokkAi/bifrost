//! Background semantic indexer.
//!
//! One worker thread per active workspace. It opens the per-repo content-addressed
//! cache, resolves the working tree to git blob OIDs, materializes any blobs the
//! cache has never seen (embedding only component texts new by content hash), then
//! builds the in-memory active index (`composed_hash → fqfn/file`) + bm25. Branch
//! switches and worktree creation reuse cached blobs, so they do almost no work.
//!
//! `semantic_search` blocks on `wait_ready` until the initial build (and any
//! queued deltas) have been applied.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::Serialize;

use crate::analyzer::{IAnalyzer, ProjectFile, WorkspaceAnalyzer};
use crate::path_utils::rel_path_string;

use super::active_index::ActiveIndex;
use super::engine::{Embedder, FakeHashEmbedder, load_production_embedder};
use super::gitcache;
use super::materialize::{BlobTarget, materialize_blobs};
use super::store::{SemanticStore, semantic_db_path};
use super::{BM25_TOKENIZER_VERSION, CHUNKER_VERSION};

/// Blobs materialized per embedding round so component texts batch well.
const FILE_GROUP: usize = 64;

/// Minimum interval between opportunistic GC sweeps (seconds).
const GC_MIN_INTERVAL_SECS: i64 = 6 * 3600;

/// Default ceiling for `wait_ready`; generous because explicit readiness
/// callers want to wait for the first build of a large repo.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const READY_TIMEOUT_MESSAGE: &str =
    "semantic index is still building; retry once indexing completes";

/// Supplies the model-backed engine; injectable so tests run without ONNX.
pub trait EngineProvider: Send + 'static {
    fn embedder(&self) -> Result<Arc<dyn Embedder>, String>;
}

/// Production provider: resolves the model from env/HF hub and loads it via Candle.
pub struct DefaultEngineProvider;

impl EngineProvider for DefaultEngineProvider {
    fn embedder(&self) -> Result<Arc<dyn Embedder>, String> {
        load_production_embedder()
    }
}

/// Deterministic engine for tests.
pub struct FakeEngineProvider {
    pub embedder: Arc<FakeHashEmbedder>,
}

impl EngineProvider for FakeEngineProvider {
    fn embedder(&self) -> Result<Arc<dyn Embedder>, String> {
        Ok(self.embedder.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Starting,
    Ready,
    Failed(String),
    Closed,
}

struct Shared {
    phase: Mutex<Phase>,
    cond: Condvar,
    closed: AtomicBool,
    pending: AtomicU64,
    store: OnceLock<Arc<SemanticStore>>,
    embedder: OnceLock<Arc<dyn Embedder>>,
}

enum IndexerMsg {
    FullBuild(Arc<WorkspaceAnalyzer>),
    Update(Arc<WorkspaceAnalyzer>, BTreeSet<ProjectFile>),
    /// Force a git-reachability GC now; the result is sent back on completion.
    /// Deliberately off the `pending`/`wait_ready` path so queries never block on it.
    Gc(Sender<Result<(), String>>),
    Shutdown,
}

pub struct SemanticIndexer {
    shared: Arc<Shared>,
    active: Arc<RwLock<Option<ActiveIndex>>>,
    tx: Sender<IndexerMsg>,
    join: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SemanticIndexStatus {
    /// Active function/summary chunks resolvable for this worktree.
    pub indexed_chunks: usize,
    pub pending_batches: u64,
    pub phase: String,
}

impl SemanticIndexer {
    pub fn start(workspace_root: PathBuf, snapshot: Arc<WorkspaceAnalyzer>) -> Arc<Self> {
        Self::start_with_provider(workspace_root, snapshot, DefaultEngineProvider)
    }

    pub fn start_with_provider(
        workspace_root: PathBuf,
        snapshot: Arc<WorkspaceAnalyzer>,
        provider: impl EngineProvider,
    ) -> Arc<Self> {
        let shared = Arc::new(Shared {
            phase: Mutex::new(Phase::Starting),
            cond: Condvar::new(),
            closed: AtomicBool::new(false),
            pending: AtomicU64::new(1),
            store: OnceLock::new(),
            embedder: OnceLock::new(),
        });
        let active: Arc<RwLock<Option<ActiveIndex>>> = Arc::new(RwLock::new(None));
        let (tx, rx) = mpsc::channel();
        tx.send(IndexerMsg::FullBuild(snapshot)).ok();
        let worker_shared = shared.clone();
        let worker_active = active.clone();
        let join = std::thread::Builder::new()
            .name("bifrost-semantic-indexer".to_string())
            .spawn(move || worker_loop(worker_shared, worker_active, workspace_root, provider, rx))
            .expect("spawn semantic indexer thread");
        Arc::new(Self {
            shared,
            active,
            tx,
            join: Mutex::new(Some(join)),
        })
    }

    pub fn request_full_build(&self, snapshot: Arc<WorkspaceAnalyzer>) {
        self.enqueue(IndexerMsg::FullBuild(snapshot));
    }

    pub fn request_update(
        &self,
        snapshot: Arc<WorkspaceAnalyzer>,
        changed_files: BTreeSet<ProjectFile>,
    ) {
        if changed_files.is_empty() {
            return;
        }
        self.enqueue(IndexerMsg::Update(snapshot, changed_files));
    }

    /// Run a forced git-reachability GC and block until it completes. Off the
    /// `wait_ready` path, so it never stalls in-flight queries; intended for
    /// occasional maintenance, not the retrieval path.
    pub fn run_gc_blocking(&self) -> Result<(), String> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err("semantic index closed".to_string());
        }
        let (done_tx, done_rx) = mpsc::channel();
        self.tx
            .send(IndexerMsg::Gc(done_tx))
            .map_err(|_| "semantic indexer worker is gone".to_string())?;
        done_rx
            .recv()
            .map_err(|_| "semantic indexer closed before gc completed".to_string())?
    }

    fn enqueue(&self, msg: IndexerMsg) {
        if self.shared.closed.load(Ordering::SeqCst) {
            return;
        }
        self.shared.pending.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(msg).is_err() {
            decrement_pending(&self.shared);
            self.shared.cond.notify_all();
        }
    }

    /// Block until the index reflects every enqueued build/update, or fail with
    /// the indexer's terminal error.
    pub fn wait_ready(&self, timeout: Duration) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        let mut phase = self
            .shared
            .phase
            .lock()
            .expect("semantic indexer mutex poisoned");
        loop {
            match &*phase {
                Phase::Failed(message) => {
                    return Err(format!("semantic index unavailable: {message}"));
                }
                Phase::Closed => return Err("semantic index closed".to_string()),
                Phase::Ready if self.shared.pending.load(Ordering::SeqCst) == 0 => return Ok(()),
                Phase::Starting | Phase::Ready => {}
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(READY_TIMEOUT_MESSAGE.to_string());
            }
            let (guard, _timed_out) = self
                .shared
                .cond
                .wait_timeout(phase, remaining)
                .expect("semantic indexer mutex poisoned");
            phase = guard;
        }
    }

    pub fn store(&self) -> Option<Arc<SemanticStore>> {
        self.shared.store.get().cloned()
    }

    pub fn embedder(&self) -> Option<Arc<dyn Embedder>> {
        self.shared.embedder.get().cloned()
    }

    /// The in-memory active index used by the query path; `None` until built.
    pub fn active_index(&self) -> Arc<RwLock<Option<ActiveIndex>>> {
        self.active.clone()
    }

    pub fn status(&self, _snapshot: &WorkspaceAnalyzer) -> SemanticIndexStatus {
        let phase = self
            .shared
            .phase
            .lock()
            .expect("semantic indexer mutex poisoned")
            .clone();
        let phase_label = match &phase {
            Phase::Starting => "starting",
            Phase::Ready => "ready",
            Phase::Failed(_) => "failed",
            Phase::Closed => "closed",
        }
        .to_string();
        let indexed_chunks = self
            .active
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|idx| idx.occurrence_count()))
            .unwrap_or(0);
        SemanticIndexStatus {
            indexed_chunks,
            pending_batches: self.shared.pending.load(Ordering::SeqCst),
            phase: phase_label,
        }
    }

    pub fn close(&self) {
        mark_closed(&self.shared);
        self.tx.send(IndexerMsg::Shutdown).ok();
        self.join
            .lock()
            .expect("semantic indexer mutex poisoned")
            .take();
    }
}

impl Drop for SemanticIndexer {
    fn drop(&mut self) {
        mark_closed(&self.shared);
        self.tx.send(IndexerMsg::Shutdown).ok();
        self.join
            .lock()
            .expect("semantic indexer mutex poisoned")
            .take();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BuildError {
    Failed(String),
    Cancelled,
}

type BuildResult<T = ()> = Result<T, BuildError>;

fn mark_closed(shared: &Shared) {
    if shared.closed.swap(true, Ordering::SeqCst) {
        return;
    }
    shared.pending.store(0, Ordering::SeqCst);
    let mut phase = shared
        .phase
        .lock()
        .expect("semantic indexer mutex poisoned");
    *phase = Phase::Closed;
    shared.cond.notify_all();
}

fn check_cancelled(shared: &Shared) -> BuildResult {
    if shared.closed.load(Ordering::SeqCst) {
        Err(BuildError::Cancelled)
    } else {
        Ok(())
    }
}

fn decrement_pending(shared: &Shared) {
    let _ = shared
        .pending
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |pending| {
            Some(pending.saturating_sub(1))
        });
}

fn worker_loop(
    shared: Arc<Shared>,
    active: Arc<RwLock<Option<ActiveIndex>>>,
    workspace_root: PathBuf,
    provider: impl EngineProvider,
    rx: Receiver<IndexerMsg>,
) {
    let fail = |shared: &Shared, message: String| {
        if shared.closed.load(Ordering::SeqCst) {
            return;
        }
        *shared
            .phase
            .lock()
            .expect("semantic indexer mutex poisoned") = Phase::Failed(message);
        shared.pending.store(0, Ordering::SeqCst);
        shared.cond.notify_all();
    };

    let Some(repo) = gitcache::discover(&workspace_root) else {
        return fail(
            &shared,
            "semantic search requires a git repository".to_string(),
        );
    };
    let store = match SemanticStore::open(&semantic_db_path(&workspace_root)) {
        Ok(store) => Arc::new(store),
        Err(err) => return fail(&shared, format!("index open failed: {err}")),
    };
    if check_cancelled(&shared).is_err() {
        return;
    }
    let embedder = match provider.embedder() {
        Ok(embedder) => embedder,
        Err(err) => return fail(&shared, format!("embedding model load failed: {err}")),
    };
    if check_cancelled(&shared).is_err() {
        return;
    }
    if let Err(err) = store.ensure_index_compatible(
        &embedder.fingerprint(),
        CHUNKER_VERSION,
        BM25_TOKENIZER_VERSION,
    ) {
        return fail(&shared, format!("index invalidation check failed: {err}"));
    }
    shared.store.set(store.clone()).ok();
    shared.embedder.set(embedder.clone()).ok();

    let mut first_build_done = false;
    while let Ok(msg) = rx.recv() {
        if check_cancelled(&shared).is_err() {
            break;
        }
        let result = match msg {
            IndexerMsg::Shutdown => break,
            IndexerMsg::Gc(done) => {
                // Forced, unthrottled; reply on the request's channel and skip
                // the readiness bookkeeping (gc doesn't affect query freshness).
                done.send(run_gc(&store, &repo)).ok();
                continue;
            }
            IndexerMsg::FullBuild(snapshot) => full_build(
                &shared,
                &store,
                embedder.as_ref(),
                &repo,
                &snapshot,
                &active,
            ),
            IndexerMsg::Update(snapshot, changed) => update_files(
                &shared,
                &store,
                embedder.as_ref(),
                &repo,
                &snapshot,
                &changed,
                &active,
            ),
        };
        match result {
            Ok(()) => {}
            Err(BuildError::Cancelled) => break,
            Err(BuildError::Failed(err)) => {
                return fail(&shared, format!("index build failed: {err}"));
            }
        }
        if !first_build_done {
            first_build_done = true;
            let mut phase = shared
                .phase
                .lock()
                .expect("semantic indexer mutex poisoned");
            if matches!(*phase, Phase::Starting) {
                *phase = Phase::Ready;
            }
        }
        decrement_pending(&shared);
        shared.cond.notify_all();
    }
}

fn full_build(
    shared: &Shared,
    store: &SemanticStore,
    embedder: &dyn Embedder,
    repo: &git2::Repository,
    snapshot: &WorkspaceAnalyzer,
    active: &RwLock<Option<ActiveIndex>>,
) -> BuildResult {
    check_cancelled(shared)?;
    let analyzer = snapshot.analyzer();
    let files: Vec<ProjectFile> = analyzer.analyzed_files().cloned().collect();
    let rel_paths: Vec<String> = files.iter().map(rel_path_string).collect();

    let path_to_oid = gitcache::working_tree_oids(repo, &rel_paths).map_err(BuildError::Failed)?;
    materialize_missing(shared, store, embedder, analyzer, &files, &path_to_oid)?;

    check_cancelled(shared)?;
    let index = ActiveIndex::build(store, &path_to_oid).map_err(BuildError::Failed)?;
    *active.write().expect("active index lock poisoned") = Some(index);

    maybe_gc(store, repo);
    Ok(())
}

fn update_files(
    shared: &Shared,
    store: &SemanticStore,
    embedder: &dyn Embedder,
    repo: &git2::Repository,
    snapshot: &WorkspaceAnalyzer,
    changed: &BTreeSet<ProjectFile>,
    active: &RwLock<Option<ActiveIndex>>,
) -> BuildResult {
    check_cancelled(shared)?;
    let analyzer = snapshot.analyzer();

    let mut changed_files: Vec<ProjectFile> = Vec::new();
    let mut removed: Vec<String> = Vec::new();
    for file in changed {
        if analyzer.is_analyzed(file) && file.exists() {
            changed_files.push(file.clone());
        } else {
            removed.push(rel_path_string(file));
        }
    }

    let rel_paths: Vec<String> = changed_files.iter().map(rel_path_string).collect();
    let path_to_oid =
        gitcache::working_tree_oids_targeted(repo, &rel_paths).map_err(BuildError::Failed)?;
    materialize_missing(
        shared,
        store,
        embedder,
        analyzer,
        &changed_files,
        &path_to_oid,
    )?;

    check_cancelled(shared)?;
    if let Some(index) = active.write().expect("active index lock poisoned").as_mut() {
        index
            .apply_changes(store, &path_to_oid, &removed)
            .map_err(BuildError::Failed)?;
    }
    Ok(())
}

/// Materialize any blobs in `path_to_oid` the cache has never seen, grouped so
/// embedding batches well. A blob (content) is materialized once even if several
/// files share it.
fn materialize_missing(
    shared: &Shared,
    store: &SemanticStore,
    embedder: &dyn Embedder,
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
    path_to_oid: &HashMap<String, String>,
) -> BuildResult {
    let mut oid_to_file: HashMap<String, ProjectFile> = HashMap::new();
    for file in files {
        let rel = rel_path_string(file);
        if let Some(oid) = path_to_oid.get(&rel) {
            oid_to_file
                .entry(oid.clone())
                .or_insert_with(|| file.clone());
        }
    }
    let oids: Vec<String> = oid_to_file.keys().cloned().collect();
    let missing = store
        .missing_blobs(&oids)
        .map_err(|e| BuildError::Failed(e.to_string()))?;

    let targets: Vec<BlobTarget> = missing
        .iter()
        .filter_map(|oid| {
            oid_to_file.get(oid).map(|file| BlobTarget {
                language: language_of(file),
                file: file.clone(),
                oid: oid.clone(),
            })
        })
        .collect();

    for group in targets.chunks(FILE_GROUP) {
        check_cancelled(shared)?;
        materialize_blobs(store, embedder, analyzer, group).map_err(BuildError::Failed)?;
    }
    Ok(())
}

fn language_of(file: &ProjectFile) -> Option<String> {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_string())
}

/// Best-effort GC: drop cache entries no longer reachable from git (or held by a
/// worktree's uncommitted working set). Throttled; failures are non-fatal.
/// Compute the live OID set (reachable ∪ each worktree's uncommitted) and sweep.
/// Used unthrottled by an explicit GC request and (throttled) by `maybe_gc`.
fn run_gc(store: &SemanticStore, repo: &git2::Repository) -> Result<(), String> {
    let mut live = gitcache::reachable_oids(repo)?;
    let roots = gitcache::worktree_roots(repo)?;
    for root in roots {
        if let Ok(dirty) = gitcache::uncommitted_oids(&root) {
            live.extend(dirty);
        }
    }
    store.gc(&live).map_err(|err| err.to_string())
}

/// Best-effort throttled GC run after a full build; errors are swallowed.
fn maybe_gc(store: &SemanticStore, repo: &git2::Repository) {
    let due = match store.seconds_since_gc() {
        Ok(Some(secs)) => secs >= GC_MIN_INTERVAL_SECS,
        Ok(None) => true,
        Err(_) => false,
    };
    if !due {
        return;
    }
    let _ = run_gc(store, repo);
}
