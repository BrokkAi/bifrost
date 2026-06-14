//! Background semantic indexer.
//!
//! One worker thread per active workspace: it loads the embedding engine,
//! reconciles the on-disk index with the current snapshot (content-hash keyed,
//! so unchanged and previously-seen texts are never re-embedded), then applies
//! watcher deltas as they stream in. `semantic_search` blocks on `wait_ready`
//! until the initial build and any queued deltas have been applied.
//!
//! Writes are idempotent (content-keyed UPSERTs, per-file transactional chunk
//! replacement), so multiple bifrost processes sharing one primary-repo DB
//! converge instead of conflicting.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use rayon::prelude::*;
use serde::Serialize;

use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::path_utils::rel_path_string;

use super::bm25::fts_text;
use super::chunker::{ChunkText, extract_file_chunks};
use super::engine::{
    Embedder, FakeHashEmbedder, FakeOverlapReranker, Reranker, load_production_embedder,
    load_production_reranker, resolve_embed_model, resolve_rerank_model,
};
use super::keys::{Key, component_key, compose, composed_key, content_hash};
use super::store::{ChunkRowIn, FileState, SemanticStore, semantic_db_path};
use super::{BM25_TOKENIZER_VERSION, CHUNKER_VERSION};

/// Files reconciled per embedding round so component texts batch well.
const FILE_GROUP: usize = 64;

/// Unreferenced component vectors survive this long (cross-branch reuse).
const COMPONENT_TTL_SECS: i64 = 30 * 24 * 3600;

/// Default ceiling for `wait_ready`; generous because explicit readiness
/// callers want to wait for the first build of a large repo.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const READY_TIMEOUT_MESSAGE: &str =
    "semantic index is still building; retry once indexing completes";

/// Supplies the model-backed engines; injectable so tests run without ONNX.
pub trait EngineProvider: Send + 'static {
    fn embedder(&self) -> Result<Arc<dyn Embedder>, String>;
    fn reranker(&self) -> Result<Arc<dyn Reranker>, String>;
}

/// Production provider: resolves models from env/HF hub and loads gte-rs.
pub struct DefaultEngineProvider;

impl EngineProvider for DefaultEngineProvider {
    fn embedder(&self) -> Result<Arc<dyn Embedder>, String> {
        let resolved = resolve_embed_model()?;
        load_production_embedder(&resolved)
    }

    fn reranker(&self) -> Result<Arc<dyn Reranker>, String> {
        let resolved = resolve_rerank_model()?;
        load_production_reranker(&resolved)
    }
}

/// Deterministic engines for tests.
pub struct FakeEngineProvider {
    pub embedder: Arc<FakeHashEmbedder>,
}

impl EngineProvider for FakeEngineProvider {
    fn embedder(&self) -> Result<Arc<dyn Embedder>, String> {
        Ok(self.embedder.clone())
    }

    fn reranker(&self) -> Result<Arc<dyn Reranker>, String> {
        Ok(Arc::new(FakeOverlapReranker))
    }
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic".to_string()
}

fn tolerate_engine_panic<T>(
    label: &str,
    load: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(load));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(result) => result,
        Err(payload) => Err(format!(
            "{label} load panicked: {}",
            panic_payload_message(payload.as_ref())
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Engine loading + initial build in progress.
    Starting,
    Ready,
    Failed(String),
    Closed,
}

struct Shared {
    phase: Mutex<Phase>,
    cond: Condvar,
    closed: AtomicBool,
    /// Delta batches enqueued but not yet applied; `wait_ready` drains this
    /// so a query never reads an index older than the snapshot it came with.
    pending: AtomicU64,
    store: OnceLock<Arc<SemanticStore>>,
    embedder: OnceLock<Arc<dyn Embedder>>,
    /// `Err` keeps the failure message so queries can degrade with a note.
    reranker: OnceLock<Result<Arc<dyn Reranker>, String>>,
    workspace_id: OnceLock<i64>,
}

enum IndexerMsg {
    FullBuild(Arc<WorkspaceAnalyzer>),
    Update(Arc<WorkspaceAnalyzer>, BTreeSet<ProjectFile>),
    Shutdown,
}

pub struct SemanticIndexer {
    shared: Arc<Shared>,
    tx: Sender<IndexerMsg>,
    join: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SemanticIndexStatus {
    pub indexed_files: usize,
    pub waiting_files: usize,
    pub pending_batches: u64,
    pub phase: String,
}

impl SemanticIndexer {
    /// Spawn the worker and queue the initial build of `snapshot`.
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
            reranker: OnceLock::new(),
            workspace_id: OnceLock::new(),
        });
        let (tx, rx) = mpsc::channel();
        tx.send(IndexerMsg::FullBuild(snapshot)).ok();
        let worker_shared = shared.clone();
        let join = std::thread::Builder::new()
            .name("bifrost-semantic-indexer".to_string())
            .spawn(move || worker_loop(worker_shared, workspace_root, provider, rx))
            .expect("spawn semantic indexer thread");
        Arc::new(Self {
            shared,
            tx,
            join: Mutex::new(Some(join)),
        })
    }

    /// Queue a full reconcile against `snapshot` (refresh / full-rescan delta).
    pub fn request_full_build(&self, snapshot: Arc<WorkspaceAnalyzer>) {
        self.enqueue(IndexerMsg::FullBuild(snapshot));
    }

    /// Queue an incremental update for watcher-reported `changed_files`.
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

    fn enqueue(&self, msg: IndexerMsg) {
        if self.shared.closed.load(Ordering::SeqCst) {
            return;
        }
        self.shared.pending.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(msg).is_err() {
            // Worker is gone; drop the claim so waiters don't hang.
            decrement_pending(&self.shared);
            self.shared.cond.notify_all();
        }
    }

    /// Block until the index reflects every enqueued build/update, or fail
    /// with the indexer's terminal error.
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

    /// `Err` carries the load failure so callers can surface a note.
    pub fn reranker(&self) -> Result<Arc<dyn Reranker>, String> {
        match self.shared.reranker.get() {
            Some(Ok(reranker)) => Ok(reranker.clone()),
            Some(Err(message)) => Err(message.clone()),
            None => Err("reranker not loaded yet".to_string()),
        }
    }

    pub fn workspace_id(&self) -> Option<i64> {
        self.shared.workspace_id.get().copied()
    }

    pub fn status(&self, snapshot: &WorkspaceAnalyzer) -> SemanticIndexStatus {
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
        let pending_batches = self.shared.pending.load(Ordering::SeqCst);
        let analyzer = snapshot.analyzer();

        let Some(store) = self.store() else {
            return SemanticIndexStatus {
                indexed_files: 0,
                waiting_files: analyzer.analyzed_files().count(),
                pending_batches,
                phase: phase_label,
            };
        };
        let Some(workspace_id) = self.workspace_id() else {
            return SemanticIndexStatus {
                indexed_files: 0,
                waiting_files: analyzer.analyzed_files().count(),
                pending_batches,
                phase: phase_label,
            };
        };
        let Ok(prior) = store.file_states(workspace_id) else {
            return SemanticIndexStatus {
                indexed_files: 0,
                waiting_files: analyzer.analyzed_files().count(),
                pending_batches,
                phase: phase_label,
            };
        };

        let mut indexed_files = 0usize;
        let mut waiting_files = 0usize;
        for file in analyzer.analyzed_files() {
            let Some(state) = current_file_state(file) else {
                continue;
            };
            let rel = rel_path_string(file);
            if prior.get(&rel).is_some_and(|prev| {
                (prev.mtime_ns == state.mtime_ns && prev.size == state.size)
                    || prev.file_hash == state.file_hash
            }) {
                indexed_files += 1;
            } else {
                waiting_files += 1;
            }
        }

        SemanticIndexStatus {
            indexed_files,
            waiting_files,
            pending_batches,
            phase: phase_label,
        }
    }

    /// Stop accepting work, wake waiters, and ask the worker to exit.
    ///
    /// This is intentionally fast: it does not wait for in-flight filesystem,
    /// SQLite, or model calls to return.
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

    let store = match SemanticStore::open(&semantic_db_path(&workspace_root)) {
        Ok(store) => Arc::new(store),
        Err(err) => return fail(&shared, format!("index open failed: {err}")),
    };
    if check_cancelled(&shared).is_err() {
        return;
    }
    let embedder = match tolerate_engine_panic("embedding model", || provider.embedder()) {
        Ok(embedder) => embedder,
        Err(err) => return fail(&shared, format!("embedding model load failed: {err}")),
    };
    if check_cancelled(&shared).is_err() {
        return;
    }
    if let Err(err) = store
        .ensure_embed_fingerprint(&embedder.fingerprint())
        .and_then(|_| store.ensure_text_versions(BM25_TOKENIZER_VERSION, CHUNKER_VERSION))
    {
        return fail(&shared, format!("index invalidation check failed: {err}"));
    }
    let workspace_id = match store.workspace_id(&workspace_root.to_string_lossy()) {
        Ok(id) => id,
        Err(err) => return fail(&shared, format!("workspace registration failed: {err}")),
    };
    shared.store.set(store.clone()).ok();
    shared.embedder.set(embedder.clone()).ok();
    shared.workspace_id.set(workspace_id).ok();

    let mut first_build_done = false;
    while let Ok(msg) = rx.recv() {
        if check_cancelled(&shared).is_err() {
            break;
        }
        let result = match msg {
            IndexerMsg::Shutdown => break,
            IndexerMsg::FullBuild(snapshot) => {
                full_build(&shared, &store, workspace_id, embedder.as_ref(), &snapshot)
            }
            IndexerMsg::Update(snapshot, changed) => update_files(
                &shared,
                &store,
                workspace_id,
                embedder.as_ref(),
                &snapshot,
                &changed,
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
            // Load the reranker after the index is usable; a failure here
            // degrades reranking but never blocks retrieval.
            shared
                .reranker
                .set(tolerate_engine_panic("reranker model", || {
                    provider.reranker()
                }))
                .ok();
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

/// Reconcile every analyzed file against the stored per-file state, then
/// drop rows for vanished files and GC unreferenced vectors.
fn full_build(
    shared: &Shared,
    store: &SemanticStore,
    workspace_id: i64,
    embedder: &dyn Embedder,
    snapshot: &WorkspaceAnalyzer,
) -> BuildResult {
    check_cancelled(shared)?;
    let analyzer = snapshot.analyzer();
    let prior = store
        .file_states(workspace_id)
        .map_err(|err| BuildError::Failed(err.to_string()))?;

    let mut present = BTreeSet::new();
    let mut stale: Vec<(ProjectFile, FileState)> = Vec::new();
    for file in analyzer.analyzed_files() {
        check_cancelled(shared)?;
        let rel = rel_path_string(file);
        let Some(state) = current_file_state(file) else {
            continue;
        };
        present.insert(rel.clone());
        let unchanged = prior.get(&rel).is_some_and(|prev| {
            (prev.mtime_ns == state.mtime_ns && prev.size == state.size)
                || prev.file_hash == state.file_hash
        });
        if !unchanged {
            stale.push((file.clone(), state));
        }
    }

    for group in stale.chunks(FILE_GROUP) {
        check_cancelled(shared)?;
        index_file_group(shared, store, workspace_id, embedder, snapshot, group)?;
    }

    let removed: Vec<String> = prior
        .keys()
        .filter(|path| !present.contains(*path))
        .cloned()
        .collect();
    if !removed.is_empty() {
        check_cancelled(shared)?;
        store
            .remove_files(workspace_id, &removed)
            .map_err(|err| BuildError::Failed(err.to_string()))?;
    }
    check_cancelled(shared)?;
    store
        .touch_built(workspace_id)
        .map_err(|err| BuildError::Failed(err.to_string()))?;
    check_cancelled(shared)?;
    store
        .gc(COMPONENT_TTL_SECS)
        .map_err(|err| BuildError::Failed(err.to_string()))?;
    Ok(())
}

/// Re-index the watcher-reported files (deleted ones drop out of the index).
fn update_files(
    shared: &Shared,
    store: &SemanticStore,
    workspace_id: i64,
    embedder: &dyn Embedder,
    snapshot: &WorkspaceAnalyzer,
    changed: &BTreeSet<ProjectFile>,
) -> BuildResult {
    check_cancelled(shared)?;
    let analyzer = snapshot.analyzer();
    let analyzed: BTreeSet<ProjectFile> = analyzer.analyzed_files().cloned().collect();

    let mut stale = Vec::new();
    let mut removed = Vec::new();
    for file in changed {
        check_cancelled(shared)?;
        match current_file_state(file) {
            Some(state) if analyzed.contains(file) => stale.push((file.clone(), state)),
            _ => removed.push(rel_path_string(file)),
        }
    }
    for group in stale.chunks(FILE_GROUP) {
        check_cancelled(shared)?;
        index_file_group(shared, store, workspace_id, embedder, snapshot, group)?;
    }
    if !removed.is_empty() {
        check_cancelled(shared)?;
        store
            .remove_files(workspace_id, &removed)
            .map_err(|err| BuildError::Failed(err.to_string()))?;
    }
    Ok(())
}

fn current_file_state(file: &ProjectFile) -> Option<FileState> {
    let abs = file.abs_path();
    let metadata = std::fs::metadata(&abs).ok()?;
    let bytes = std::fs::read(&abs).ok()?;
    let mtime_ns = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    Some(FileState {
        file_hash: content_hash(&bytes),
        mtime_ns,
        size: metadata.len() as i64,
    })
}

/// One reconcile round: extract chunks for the group, embed only component
/// texts the store has never seen, compose missing chunk vectors, then
/// replace each file's chunk rows transactionally.
fn index_file_group(
    shared: &Shared,
    store: &SemanticStore,
    workspace_id: i64,
    embedder: &dyn Embedder,
    snapshot: &WorkspaceAnalyzer,
    group: &[(ProjectFile, FileState)],
) -> BuildResult {
    check_cancelled(shared)?;
    let analyzer = snapshot.analyzer();
    let count_tokens = |text: &str| embedder.count_tokens(text);

    struct PendingChunk {
        chunk: ChunkText,
        child_key: Key,
        parent_key: Option<Key>,
        composed: Key,
    }
    struct PendingFile {
        rel_path: String,
        state: FileState,
        chunks: Vec<PendingChunk>,
    }

    let mut pending_files = Vec::with_capacity(group.len());
    let mut component_texts: Vec<(Key, String)> = Vec::new();
    let mut seen_components: BTreeSet<Key> = BTreeSet::new();
    for (file, state) in group {
        check_cancelled(shared)?;
        let extracted = extract_file_chunks(analyzer, file, &count_tokens);
        let mut chunks = Vec::with_capacity(extracted.chunks.len());
        for chunk in extracted.chunks {
            let child_key = component_key(&chunk.text);
            if seen_components.insert(child_key) {
                component_texts.push((child_key, chunk.text.clone()));
            }
            let parent_key = chunk.parent_text.as_deref().map(component_key);
            if let (Some(key), Some(text)) = (parent_key, chunk.parent_text.as_deref())
                && seen_components.insert(key)
            {
                component_texts.push((key, text.to_string()));
            }
            let composed = match parent_key {
                Some(parent) => composed_key(&child_key, &parent),
                None => child_key,
            };
            chunks.push(PendingChunk {
                chunk,
                child_key,
                parent_key,
                composed,
            });
        }
        pending_files.push(PendingFile {
            rel_path: extracted.file_path,
            state: state.clone(),
            chunks,
        });
    }

    let (build_result, fts_per_file) = std::thread::scope(|scope| {
        // BM25 tokenization is pure over chunk text, so hide it under the
        // embed/store window while the main thread preserves the existing flow.
        let fts_handle = scope.spawn(|| {
            pending_files
                .par_iter()
                .map(|file| {
                    file.chunks
                        .iter()
                        .map(|chunk| fts_text(&chunk.chunk.text))
                        .collect()
                })
                .collect::<Vec<Vec<String>>>()
        });

        let build_result = (|| -> BuildResult {
            // Embed component texts the store doesn't have yet.
            check_cancelled(shared)?;
            let all_component_keys: Vec<Key> =
                component_texts.iter().map(|(key, _)| *key).collect();
            let missing: BTreeSet<Key> = store
                .missing_component_keys(&all_component_keys)
                .map_err(|err| BuildError::Failed(err.to_string()))?
                .into_iter()
                .collect();
            let to_embed: Vec<&(Key, String)> = component_texts
                .iter()
                .filter(|(key, _)| missing.contains(key))
                .collect();
            if !to_embed.is_empty() {
                check_cancelled(shared)?;
                let texts: Vec<&str> = to_embed.iter().map(|(_, text)| text.as_str()).collect();
                let vectors = embedder
                    .embed_passages(&texts)
                    .map_err(BuildError::Failed)?;
                check_cancelled(shared)?;
                let items: Vec<(Key, Vec<f32>)> =
                    to_embed.iter().map(|(key, _)| *key).zip(vectors).collect();
                store
                    .upsert_component_vectors(&items)
                    .map_err(|err| BuildError::Failed(err.to_string()))?;
            }

            // Compose missing chunk vectors from their (now cached) components.
            check_cancelled(shared)?;
            let composed_keys: Vec<Key> = pending_files
                .iter()
                .flat_map(|file| file.chunks.iter().map(|chunk| chunk.composed))
                .collect();
            let missing_composed: BTreeSet<Key> = store
                .missing_composed_keys(&composed_keys)
                .map_err(|err| BuildError::Failed(err.to_string()))?
                .into_iter()
                .collect();
            let mut needed_components: BTreeSet<Key> = BTreeSet::new();
            for file in &pending_files {
                for chunk in &file.chunks {
                    if missing_composed.contains(&chunk.composed) {
                        needed_components.insert(chunk.child_key);
                        if let Some(parent) = chunk.parent_key {
                            needed_components.insert(parent);
                        }
                    }
                }
            }
            let component_vectors = store
                .component_vectors(&needed_components.iter().copied().collect::<Vec<_>>())
                .map_err(|err| BuildError::Failed(err.to_string()))?;
            let mut composed_items: Vec<(Key, Vec<f32>)> = Vec::new();
            let mut emitted: BTreeSet<Key> = BTreeSet::new();
            for file in &pending_files {
                check_cancelled(shared)?;
                for chunk in &file.chunks {
                    if !missing_composed.contains(&chunk.composed)
                        || !emitted.insert(chunk.composed)
                    {
                        continue;
                    }
                    let Some(child) = component_vectors.get(&chunk.child_key) else {
                        return Err(BuildError::Failed(
                            "component vector missing after embed".to_string(),
                        ));
                    };
                    let vector = match chunk.parent_key {
                        Some(parent_key) => {
                            let Some(parent) = component_vectors.get(&parent_key) else {
                                return Err(BuildError::Failed(
                                    "parent component vector missing after embed".to_string(),
                                ));
                            };
                            compose(child, parent)
                        }
                        None => child.clone(),
                    };
                    composed_items.push((chunk.composed, vector));
                }
            }
            if !composed_items.is_empty() {
                check_cancelled(shared)?;
                store
                    .upsert_composed_vectors(&composed_items)
                    .map_err(|err| BuildError::Failed(err.to_string()))?;
            }

            Ok(())
        })();

        (build_result, fts_handle.join().unwrap())
    });

    build_result?;

    // Replace each file's chunk index rows (and bm25 docs for new texts).
    for (file, fts) in pending_files.iter().zip(fts_per_file) {
        check_cancelled(shared)?;
        let rows: Vec<ChunkRowIn> = file
            .chunks
            .iter()
            .zip(&fts)
            .map(|(chunk, tokens)| ChunkRowIn {
                chunk_ord: chunk.chunk.ord,
                kind: chunk.chunk.kind.as_str(),
                symbol: chunk.chunk.symbol.as_deref(),
                start_line: chunk.chunk.start_line,
                end_line: chunk.chunk.end_line,
                composed_key: chunk.composed,
                text_hash: content_hash(chunk.chunk.text.as_bytes()),
                fts_tokens: tokens,
            })
            .collect();
        store
            .replace_file_chunks(workspace_id, &file.rel_path, &file.state, &rows)
            .map_err(|err| BuildError::Failed(err.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, FilesystemProject, Project};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Instant;

    fn write_java(dir: &Path, name: &str, class_body: &str) {
        std::fs::write(dir.join(name), class_body).unwrap();
    }

    fn snapshot_for(root: &Path) -> Arc<WorkspaceAnalyzer> {
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(root.to_path_buf()).unwrap());
        Arc::new(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()))
    }

    fn start_fake(
        root: &Path,
        snapshot: Arc<WorkspaceAnalyzer>,
    ) -> (Arc<SemanticIndexer>, Arc<FakeHashEmbedder>) {
        let embedder = Arc::new(FakeHashEmbedder::new(16));
        let indexer = SemanticIndexer::start_with_provider(
            root.to_path_buf(),
            snapshot,
            FakeEngineProvider {
                embedder: embedder.clone(),
            },
        );
        (indexer, embedder)
    }

    struct BlockingEmbedder {
        state: Mutex<BlockingState>,
        entered: Condvar,
        released: Condvar,
        calls: AtomicUsize,
    }

    struct BlockingState {
        in_embed: bool,
        release: bool,
    }

    impl BlockingEmbedder {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(BlockingState {
                    in_embed: false,
                    release: false,
                }),
                entered: Condvar::new(),
                released: Condvar::new(),
                calls: AtomicUsize::new(0),
            })
        }

        fn wait_until_embedding(&self) {
            let mut state = self.state.lock().expect("blocking embedder mutex poisoned");
            while !state.in_embed {
                state = self
                    .entered
                    .wait(state)
                    .expect("blocking embedder mutex poisoned");
            }
        }

        fn release(&self) {
            let mut state = self.state.lock().expect("blocking embedder mutex poisoned");
            state.release = true;
            self.released.notify_all();
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Embedder for BlockingEmbedder {
        fn dim(&self) -> usize {
            1
        }

        fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().expect("blocking embedder mutex poisoned");
            state.in_embed = true;
            self.entered.notify_all();
            while !state.release {
                state = self
                    .released
                    .wait(state)
                    .expect("blocking embedder mutex poisoned");
            }
            Ok(texts.iter().map(|_| vec![1.0]).collect())
        }

        fn embed_query(&self, _text: &str) -> Result<Vec<f32>, String> {
            Ok(vec![1.0])
        }

        fn count_tokens(&self, text: &str) -> usize {
            text.split_whitespace().count()
        }

        fn fingerprint(&self) -> String {
            "blocking-test-embedder:v1".to_string()
        }
    }

    struct BlockingEngineProvider {
        embedder: Arc<BlockingEmbedder>,
    }

    impl EngineProvider for BlockingEngineProvider {
        fn embedder(&self) -> Result<Arc<dyn Embedder>, String> {
            Ok(self.embedder.clone())
        }

        fn reranker(&self) -> Result<Arc<dyn Reranker>, String> {
            Ok(Arc::new(FakeOverlapReranker))
        }
    }

    struct PanickingEngineProvider;

    impl EngineProvider for PanickingEngineProvider {
        fn embedder(&self) -> Result<Arc<dyn Embedder>, String> {
            panic!("missing ONNX runtime")
        }

        fn reranker(&self) -> Result<Arc<dyn Reranker>, String> {
            Ok(Arc::new(FakeOverlapReranker))
        }
    }

    #[test]
    fn engine_load_panic_marks_semantic_index_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        write_java(
            dir.path(),
            "Thing.java",
            "public class Thing { public String value() { return \"x\"; } }\n",
        );
        let snapshot = snapshot_for(dir.path());
        let indexer = SemanticIndexer::start_with_provider(
            dir.path().to_path_buf(),
            snapshot,
            PanickingEngineProvider,
        );

        let err = indexer
            .wait_ready(Duration::from_secs(30))
            .expect_err("panicking engine provider should fail semantic indexing");

        assert!(err.contains("semantic index unavailable"));
        assert!(err.contains("missing ONNX runtime"));
        indexer.close();
    }

    #[test]
    fn close_returns_quickly_while_embedding_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..80 {
            write_java(
                dir.path(),
                &format!("Thing{index}.java"),
                &format!(
                    "public class Thing{index} {{\n  public String value{index}() {{ return \"{index}\"; }}\n}}\n"
                ),
            );
        }
        let snapshot = snapshot_for(dir.path());
        let embedder = BlockingEmbedder::new();
        let indexer = SemanticIndexer::start_with_provider(
            dir.path().to_path_buf(),
            snapshot,
            BlockingEngineProvider {
                embedder: embedder.clone(),
            },
        );
        embedder.wait_until_embedding();

        let started = Instant::now();
        indexer.close();
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "close should not wait for blocked embedding"
        );
        let err = indexer
            .wait_ready(Duration::from_secs(30))
            .expect_err("closed indexer should wake waiters");
        assert_eq!(err, "semantic index closed");

        embedder.release();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            embedder.calls(),
            1,
            "closed indexer should not continue to later file groups"
        );
    }

    #[test]
    fn initial_build_blocks_then_indexes() {
        let dir = tempfile::tempdir().unwrap();
        write_java(
            dir.path(),
            "Greeter.java",
            "public class Greeter {\n  public String greet(String name) { return \"hi \" + name; }\n}\n",
        );
        let snapshot = snapshot_for(dir.path());
        let (indexer, embedder) = start_fake(dir.path(), snapshot);

        indexer.wait_ready(Duration::from_secs(30)).unwrap();
        assert!(embedder.texts_embedded() > 0);

        let store = indexer.store().unwrap();
        let workspace_id = indexer.workspace_id().unwrap();
        let mut rows = 0usize;
        store
            .scan_vectors(workspace_id, 16, &mut |batch| rows += batch.len())
            .unwrap();
        assert!(rows >= 2, "expected summary + method chunks, got {rows}");
        indexer.close();
    }

    #[test]
    fn unchanged_rebuild_embeds_nothing_new() {
        let dir = tempfile::tempdir().unwrap();
        write_java(
            dir.path(),
            "Greeter.java",
            "public class Greeter {\n  public String greet(String name) { return \"hi \" + name; }\n}\n",
        );
        let snapshot = snapshot_for(dir.path());
        let (indexer, embedder) = start_fake(dir.path(), snapshot.clone());
        indexer.wait_ready(Duration::from_secs(30)).unwrap();
        let after_first = embedder.texts_embedded();

        indexer.request_full_build(snapshot);
        indexer.wait_ready(Duration::from_secs(30)).unwrap();
        assert_eq!(embedder.texts_embedded(), after_first);
        indexer.close();
    }

    #[test]
    fn branch_switch_back_reuses_cached_vectors() {
        let dir = tempfile::tempdir().unwrap();
        let original = "public class Greeter {\n  public String greet(String name) { return \"hi \" + name; }\n}\n";
        let edited = "public class Greeter {\n  public String greet(String name) { return \"hello \" + name; }\n}\n";
        write_java(dir.path(), "Greeter.java", original);
        let snapshot = snapshot_for(dir.path());
        let (indexer, embedder) = start_fake(dir.path(), snapshot.clone());
        indexer.wait_ready(Duration::from_secs(30)).unwrap();

        // "Switch branch": new content embeds new component texts.
        write_java(dir.path(), "Greeter.java", edited);
        let file = snapshot
            .analyzer()
            .analyzed_files()
            .next()
            .cloned()
            .unwrap();
        let changed: BTreeSet<ProjectFile> = [file.clone()].into_iter().collect();
        let snapshot2 = Arc::new(snapshot.update(&changed));
        indexer.request_update(snapshot2.clone(), changed.clone());
        indexer.wait_ready(Duration::from_secs(30)).unwrap();
        let after_edit = embedder.texts_embedded();
        assert!(after_edit > 0);

        // "Switch back": every component text is already cached.
        write_java(dir.path(), "Greeter.java", original);
        let snapshot3 = Arc::new(snapshot2.update(&changed));
        indexer.request_update(snapshot3, changed);
        indexer.wait_ready(Duration::from_secs(30)).unwrap();
        assert_eq!(
            embedder.texts_embedded(),
            after_edit,
            "revert must reuse cached vectors"
        );
        indexer.close();
    }

    #[test]
    fn deleted_file_drops_out_of_index() {
        let dir = tempfile::tempdir().unwrap();
        write_java(
            dir.path(),
            "Greeter.java",
            "public class Greeter {\n  public String greet(String name) { return \"hi \" + name; }\n}\n",
        );
        write_java(
            dir.path(),
            "Other.java",
            "public class Other {\n  public int answer() { return 42; }\n}\n",
        );
        let snapshot = snapshot_for(dir.path());
        let (indexer, _embedder) = start_fake(dir.path(), snapshot.clone());
        indexer.wait_ready(Duration::from_secs(30)).unwrap();

        let other = snapshot
            .analyzer()
            .analyzed_files()
            .find(|file| rel_path_string(file) == "Other.java")
            .cloned()
            .unwrap();
        std::fs::remove_file(other.abs_path()).unwrap();
        let changed: BTreeSet<ProjectFile> = [other].into_iter().collect();
        let snapshot2 = Arc::new(snapshot.update(&changed));
        indexer.request_update(snapshot2, changed);
        indexer.wait_ready(Duration::from_secs(30)).unwrap();

        let store = indexer.store().unwrap();
        let workspace_id = indexer.workspace_id().unwrap();
        let mut paths = BTreeSet::new();
        store
            .scan_vectors(workspace_id, 16, &mut |batch| {
                paths.extend(batch.into_iter().map(|row| row.file_path));
            })
            .unwrap();
        assert!(paths.contains("Greeter.java"));
        assert!(!paths.contains("Other.java"));
        indexer.close();
    }
}
