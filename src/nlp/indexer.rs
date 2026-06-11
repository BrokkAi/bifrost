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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::path_utils::rel_path_string;

use super::bm25::fts_text;
use super::chunker::{ChunkText, extract_file_chunks};
use super::engine::{
    Embedder, FakeHashEmbedder, FakeOverlapReranker, GteEmbedder, GteReranker, Reranker,
    resolve_embed_model, resolve_rerank_model,
};
use super::keys::{Key, component_key, compose, composed_key, content_hash};
use super::store::{ChunkRowIn, FileState, SemanticStore, semantic_db_path};
use super::{BM25_TOKENIZER_VERSION, CHUNKER_VERSION};

/// Files reconciled per embedding round so component texts batch well.
const FILE_GROUP: usize = 64;

/// Unreferenced component vectors survive this long (cross-branch reuse).
const COMPONENT_TTL_SECS: i64 = 30 * 24 * 3600;

/// Default ceiling for `wait_ready`; generous because the first build of a
/// large repo embeds every chunk.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30 * 60);

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
        Ok(Arc::new(GteEmbedder::load(&resolved)?))
    }

    fn reranker(&self) -> Result<Arc<dyn Reranker>, String> {
        let resolved = resolve_rerank_model()?;
        Ok(Arc::new(GteReranker::load(&resolved)?))
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
        self.shared.pending.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(msg).is_err() {
            // Worker is gone; drop the claim so waiters don't hang.
            self.shared.pending.fetch_sub(1, Ordering::SeqCst);
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
                return Err(
                    "semantic index is still building; retry once indexing completes".to_string(),
                );
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

    /// Stop the worker and wait for it to exit. Safe to call more than once.
    pub fn close(&self) {
        self.tx.send(IndexerMsg::Shutdown).ok();
        if let Some(join) = self
            .join
            .lock()
            .expect("semantic indexer mutex poisoned")
            .take()
        {
            join.join().ok();
        }
        let mut phase = self
            .shared
            .phase
            .lock()
            .expect("semantic indexer mutex poisoned");
        if !matches!(*phase, Phase::Failed(_)) {
            *phase = Phase::Closed;
        }
        self.shared.cond.notify_all();
    }
}

impl Drop for SemanticIndexer {
    fn drop(&mut self) {
        // Detach rather than join: a workspace switch must not block on an
        // in-flight build. The worker drains its current message, sees the
        // Shutdown (or a closed channel), and exits on its own.
        self.tx.send(IndexerMsg::Shutdown).ok();
        self.join
            .lock()
            .expect("semantic indexer mutex poisoned")
            .take();
    }
}

fn worker_loop(
    shared: Arc<Shared>,
    workspace_root: PathBuf,
    provider: impl EngineProvider,
    rx: Receiver<IndexerMsg>,
) {
    let fail = |shared: &Shared, message: String| {
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
    let embedder = match provider.embedder() {
        Ok(embedder) => embedder,
        Err(err) => return fail(&shared, format!("embedding model load failed: {err}")),
    };
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
        let result = match msg {
            IndexerMsg::Shutdown => break,
            IndexerMsg::FullBuild(snapshot) => {
                full_build(&store, workspace_id, embedder.as_ref(), &snapshot)
            }
            IndexerMsg::Update(snapshot, changed) => {
                update_files(&store, workspace_id, embedder.as_ref(), &snapshot, &changed)
            }
        };
        if let Err(err) = result {
            return fail(&shared, format!("index build failed: {err}"));
        }
        if !first_build_done {
            first_build_done = true;
            // Load the reranker after the index is usable; a failure here
            // degrades reranking but never blocks retrieval.
            shared.reranker.set(provider.reranker()).ok();
            let mut phase = shared
                .phase
                .lock()
                .expect("semantic indexer mutex poisoned");
            if matches!(*phase, Phase::Starting) {
                *phase = Phase::Ready;
            }
        }
        shared.pending.fetch_sub(1, Ordering::SeqCst);
        shared.cond.notify_all();
    }
}

/// Reconcile every analyzed file against the stored per-file state, then
/// drop rows for vanished files and GC unreferenced vectors.
fn full_build(
    store: &SemanticStore,
    workspace_id: i64,
    embedder: &dyn Embedder,
    snapshot: &WorkspaceAnalyzer,
) -> Result<(), String> {
    let analyzer = snapshot.analyzer();
    let prior = store
        .file_states(workspace_id)
        .map_err(|err| err.to_string())?;

    let mut present = BTreeSet::new();
    let mut stale: Vec<(ProjectFile, FileState)> = Vec::new();
    for file in analyzer.analyzed_files() {
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
        index_file_group(store, workspace_id, embedder, snapshot, group)?;
    }

    let removed: Vec<String> = prior
        .keys()
        .filter(|path| !present.contains(*path))
        .cloned()
        .collect();
    if !removed.is_empty() {
        store
            .remove_files(workspace_id, &removed)
            .map_err(|err| err.to_string())?;
    }
    store
        .touch_built(workspace_id)
        .map_err(|err| err.to_string())?;
    store
        .gc(COMPONENT_TTL_SECS)
        .map_err(|err| err.to_string())?;
    Ok(())
}

/// Re-index the watcher-reported files (deleted ones drop out of the index).
fn update_files(
    store: &SemanticStore,
    workspace_id: i64,
    embedder: &dyn Embedder,
    snapshot: &WorkspaceAnalyzer,
    changed: &BTreeSet<ProjectFile>,
) -> Result<(), String> {
    let analyzer = snapshot.analyzer();
    let analyzed: BTreeSet<ProjectFile> = analyzer.analyzed_files().cloned().collect();

    let mut stale = Vec::new();
    let mut removed = Vec::new();
    for file in changed {
        match current_file_state(file) {
            Some(state) if analyzed.contains(file) => stale.push((file.clone(), state)),
            _ => removed.push(rel_path_string(file)),
        }
    }
    for group in stale.chunks(FILE_GROUP) {
        index_file_group(store, workspace_id, embedder, snapshot, group)?;
    }
    if !removed.is_empty() {
        store
            .remove_files(workspace_id, &removed)
            .map_err(|err| err.to_string())?;
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
    store: &SemanticStore,
    workspace_id: i64,
    embedder: &dyn Embedder,
    snapshot: &WorkspaceAnalyzer,
    group: &[(ProjectFile, FileState)],
) -> Result<(), String> {
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

    // Embed component texts the store doesn't have yet.
    let all_component_keys: Vec<Key> = component_texts.iter().map(|(key, _)| *key).collect();
    let missing: BTreeSet<Key> = store
        .missing_component_keys(&all_component_keys)
        .map_err(|err| err.to_string())?
        .into_iter()
        .collect();
    let to_embed: Vec<&(Key, String)> = component_texts
        .iter()
        .filter(|(key, _)| missing.contains(key))
        .collect();
    if !to_embed.is_empty() {
        let texts: Vec<&str> = to_embed.iter().map(|(_, text)| text.as_str()).collect();
        let vectors = embedder.embed_passages(&texts)?;
        let items: Vec<(Key, Vec<f32>)> =
            to_embed.iter().map(|(key, _)| *key).zip(vectors).collect();
        store
            .upsert_component_vectors(&items)
            .map_err(|err| err.to_string())?;
    }

    // Compose missing chunk vectors from their (now cached) components.
    let composed_keys: Vec<Key> = pending_files
        .iter()
        .flat_map(|file| file.chunks.iter().map(|chunk| chunk.composed))
        .collect();
    let missing_composed: BTreeSet<Key> = store
        .missing_composed_keys(&composed_keys)
        .map_err(|err| err.to_string())?
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
        .map_err(|err| err.to_string())?;
    let mut composed_items: Vec<(Key, Vec<f32>)> = Vec::new();
    let mut emitted: BTreeSet<Key> = BTreeSet::new();
    for file in &pending_files {
        for chunk in &file.chunks {
            if !missing_composed.contains(&chunk.composed) || !emitted.insert(chunk.composed) {
                continue;
            }
            let Some(child) = component_vectors.get(&chunk.child_key) else {
                return Err("component vector missing after embed".to_string());
            };
            let vector = match chunk.parent_key {
                Some(parent_key) => {
                    let Some(parent) = component_vectors.get(&parent_key) else {
                        return Err("parent component vector missing after embed".to_string());
                    };
                    compose(child, parent)
                }
                None => child.clone(),
            };
            composed_items.push((chunk.composed, vector));
        }
    }
    if !composed_items.is_empty() {
        store
            .upsert_composed_vectors(&composed_items)
            .map_err(|err| err.to_string())?;
    }

    // Replace each file's chunk index rows (and bm25 docs for new texts).
    for file in &pending_files {
        let fts: Vec<String> = file
            .chunks
            .iter()
            .map(|chunk| fts_text(&chunk.chunk.text))
            .collect();
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
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, FilesystemProject, Project};
    use std::path::Path;

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
