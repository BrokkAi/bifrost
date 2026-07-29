//! Embedding engine.
//!
//! `Embedder` is the seam the indexer and query pipeline depend on; the production impl
//! ([`super::voyage_sidecar`]) runs voyageai/voyage-4-nano in a PyTorch SDPA sidecar
//! (one process per device, fused attention on CUDA/Metal/CPU), and a deterministic fake
//! backs the model-free tests. Model files resolve from an env-pointed local directory
//! first (fine-tune escape hatch), then the HF hub cache. The sidecar selects its device
//! at runtime; [`accelerator_available`] only decides whether to advertise the tool.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use super::keys::l2_normalize;
use super::{PARENT_ALPHA, PASSAGE_PREFIX, QUERY_PREFIX, REPRESENTATION_KIND};

pub trait Embedder: Send + Sync {
    fn dim(&self) -> usize;

    /// Embed document texts; the passage prefix is applied here, exactly once.
    /// Outputs are L2-normalized.
    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String>;

    /// Embed a search query; the query prefix is applied here, exactly once.
    fn embed_query(&self, text: &str) -> Result<Vec<f32>, String>;

    /// Token count under the embedding model's tokenizer (no special tokens).
    fn count_tokens(&self, text: &str) -> usize;

    /// Identifies the model + text contract; a change invalidates all cached
    /// vectors (checked against the index's meta table on every open).
    fn fingerprint(&self) -> String;
}

/// Fingerprint recipe shared by all embedders: model label + dimensionality +
/// the exact prefix strings + vector representation contract.
pub(crate) fn fingerprint_for(label: &str, dim: usize) -> String {
    let mut hasher = Sha256::new();
    for part in [
        label,
        &dim.to_string(),
        QUERY_PREFIX,
        PASSAGE_PREFIX,
        REPRESENTATION_KIND,
        &format!("alpha={PARENT_ALPHA}"),
        // Stored-vector format. Bumping this invalidates caches written in a prior
        // format (e.g. raw f32 before fastrq) without changing the content keys.
        "storage=rq8_v1",
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("embed_v1:{hex}")
}

// ---------------------------------------------------------------------------
// Model resolution
// ---------------------------------------------------------------------------

pub const DEFAULT_EMBED_MODEL_ID: &str = "voyageai/voyage-4-nano";

pub const EMBED_MODEL_DIR_ENV: &str = "BIFROST_EMBED_MODEL_DIR";
pub const EMBED_MODEL_ID_ENV: &str = "BIFROST_EMBED_MODEL_ID";
const ACCELERATOR_ENV: &str = "BIFROST_ACCELERATOR";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceleratorPreference {
    Auto,
    Cpu,
    Cuda,
    Metal,
}

fn accelerator_preference() -> AcceleratorPreference {
    match std::env::var(ACCELERATOR_ENV).ok().as_deref() {
        Some("cpu") => AcceleratorPreference::Cpu,
        Some("cuda") | Some("gpu") => AcceleratorPreference::Cuda,
        Some("metal") | Some("coreml") | Some("core-ml") => AcceleratorPreference::Metal,
        _ => AcceleratorPreference::Auto,
    }
}

/// Whether `nvidia-smi` reports at least one CUDA GPU. The sidecar enumerates devices
/// the same way, so this mirrors what the embedder will actually run on.
fn cuda_present() -> bool {
    std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=uuid", "--format=csv,noheader"])
        .output()
        .map(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|line| !line.trim().is_empty())
        })
        .unwrap_or(false)
}

/// Whether a Metal GPU is present: every Mac that runs this binary has one.
fn metal_present() -> bool {
    cfg!(target_os = "macos")
}

/// Whether a CUDA or Metal accelerator is available under the current preference.
/// Drives whether `semantic_search` is offered (an explicit `cpu` preference reports
/// `false` — it must be force-enabled). The model runs in the PyTorch sidecar, which
/// picks its own device at runtime; this only decides whether to advertise the tool.
pub fn accelerator_available() -> bool {
    match accelerator_preference() {
        AcceleratorPreference::Cpu => false,
        AcceleratorPreference::Cuda => cuda_present(),
        AcceleratorPreference::Metal => metal_present(),
        AcceleratorPreference::Auto => cuda_present() || metal_present(),
    }
}

pub(crate) fn embed_repo_id() -> String {
    std::env::var(EMBED_MODEL_ID_ENV).unwrap_or_else(|_| DEFAULT_EMBED_MODEL_ID.to_string())
}

/// Directory holding the model's `config.json`, `tokenizer.json`, and
/// `model.safetensors`. Resolves from `BIFROST_EMBED_MODEL_DIR` first, else
/// downloads (or reuses the cache of) the HF repo.
pub(crate) fn resolve_embed_model_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var(EMBED_MODEL_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let api = hf_hub::api::sync::Api::new().map_err(|err| format!("hf-hub init failed: {err}"))?;
    let repo = api.model(embed_repo_id());
    let fetch = |name: &str| -> Result<PathBuf, String> {
        repo.get(name)
            .map_err(|err| format!("fetch {name} from {}: {err}", embed_repo_id()))
    };
    fetch("config.json")?;
    fetch("tokenizer.json")?;
    let weights = fetch("model.safetensors")?;
    weights
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "model weights have no parent directory".to_string())
}

pub fn load_production_embedder() -> Result<Arc<dyn Embedder>, String> {
    // voyage-4-nano runs in the PyTorch SDPA sidecar (fused attention on every backend,
    // incl. Blackwell sm_120 where candle/flash-attn could not). The sidecar spawns one
    // process per device and fans the batch across them via `ScheduledEmbedder`.
    super::voyage_sidecar::load_sidecar_embedder()
}

/// Smallest pull, to keep GPU batches efficient (avoid kernel-launch-bound tiny calls).
const MIN_SCHEDULE_CHUNK: usize = 8;
/// Target pulls per worker per batch: enough for dynamic load-balancing (faster GPUs
/// pull more) while still engaging every worker on a modest batch.
const PULLS_PER_WORKER: usize = 4;

/// Fans `embed_passages` across one embedder per GPU via a shared pull queue, so a
/// single repo's index uses every visible device. Queries (a single vector) run on
/// the first worker.
pub struct ScheduledEmbedder {
    workers: Vec<Arc<dyn Embedder>>,
}

impl ScheduledEmbedder {
    pub fn new(workers: Vec<Arc<dyn Embedder>>) -> Self {
        assert!(
            !workers.is_empty(),
            "ScheduledEmbedder needs at least one worker"
        );
        Self { workers }
    }
}

impl Embedder for ScheduledEmbedder {
    fn dim(&self) -> usize {
        self.workers[0].dim()
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        let n = self.workers.len();
        // Pull granularity: aim for ~PULLS_PER_WORKER pulls each, so every GPU gets a
        // share of a modest batch yet a faster GPU can still pull extra.
        let chunk = (texts.len() / (n * PULLS_PER_WORKER)).max(MIN_SCHEDULE_CHUNK);
        if n == 1 || texts.len() <= chunk {
            return self.workers[0].embed_passages(texts);
        }
        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<Vec<f32>>> = Mutex::new(vec![Vec::new(); texts.len()]);
        let first_err: Mutex<Option<String>> = Mutex::new(None);
        std::thread::scope(|scope| {
            for worker in &self.workers {
                scope.spawn(|| {
                    loop {
                        if first_err.lock().expect("schedule err lock").is_some() {
                            return;
                        }
                        let start = next.fetch_add(chunk, Ordering::SeqCst);
                        if start >= texts.len() {
                            return;
                        }
                        let end = (start + chunk).min(texts.len());
                        match worker.embed_passages(&texts[start..end]) {
                            Ok(vecs) => {
                                let mut guard = results.lock().expect("schedule results lock");
                                for (offset, vec) in vecs.into_iter().enumerate() {
                                    guard[start + offset] = vec;
                                }
                            }
                            Err(err) => {
                                *first_err.lock().expect("schedule err lock") = Some(err);
                                return;
                            }
                        }
                    }
                });
            }
        });
        if let Some(err) = first_err.into_inner().expect("schedule err lock") {
            return Err(err);
        }
        Ok(results.into_inner().expect("schedule results lock"))
    }

    fn embed_query(&self, text: &str) -> Result<Vec<f32>, String> {
        self.workers[0].embed_query(text)
    }

    fn count_tokens(&self, text: &str) -> usize {
        self.workers[0].count_tokens(text)
    }

    fn fingerprint(&self) -> String {
        self.workers[0].fingerprint()
    }
}

// ---------------------------------------------------------------------------
// Deterministic fake for model-free tests
// ---------------------------------------------------------------------------

/// Test-only embedder: pseudo-vectors derived from sha256 of the text, so
/// identical texts collide and similarity is deterministic. Counts embed
/// calls so tests can assert cache hits (e.g. zero re-embeds after a branch
/// switch).
pub struct FakeHashEmbedder {
    dim: usize,
    calls: AtomicUsize,
    texts_embedded: AtomicUsize,
}

impl FakeHashEmbedder {
    pub fn new(dim: usize) -> Self {
        Self {
            dim,
            calls: AtomicUsize::new(0),
            texts_embedded: AtomicUsize::new(0),
        }
    }

    pub fn embed_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn texts_embedded(&self) -> usize {
        self.texts_embedded.load(Ordering::SeqCst)
    }

    fn vector_for(&self, text: &str) -> Vec<f32> {
        let mut vector = Vec::with_capacity(self.dim);
        let mut counter = 0u32;
        while vector.len() < self.dim {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            hasher.update(counter.to_le_bytes());
            for pair in hasher.finalize().chunks(2) {
                if vector.len() == self.dim {
                    break;
                }
                let raw = u16::from_le_bytes([pair[0], pair[1]]) as f32;
                vector.push(raw / u16::MAX as f32 - 0.5);
            }
            counter += 1;
        }
        l2_normalize(&mut vector);
        vector
    }
}

impl Embedder for FakeHashEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.texts_embedded.fetch_add(texts.len(), Ordering::SeqCst);
        Ok(texts.iter().map(|text| self.vector_for(text)).collect())
    }

    fn embed_query(&self, text: &str) -> Result<Vec<f32>, String> {
        Ok(self.vector_for(text))
    }

    fn count_tokens(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }

    fn fingerprint(&self) -> String {
        fingerprint_for("fake-hash-embedder", self.dim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_embedder_is_deterministic_and_normalized() {
        let embedder = FakeHashEmbedder::new(16);
        let a = embedder.embed_passages(&["hello"]).unwrap();
        let b = embedder.embed_passages(&["hello"]).unwrap();
        assert_eq!(a, b);
        let norm: f32 = a[0].iter().map(|v| v * v).sum();
        assert!((norm - 1.0).abs() < 1e-5);
        assert_eq!(embedder.embed_calls(), 2);
        assert_eq!(embedder.texts_embedded(), 2);
    }

    #[test]
    fn fake_embedder_distinguishes_texts() {
        let embedder = FakeHashEmbedder::new(16);
        let vectors = embedder.embed_passages(&["alpha", "beta"]).unwrap();
        assert_ne!(vectors[0], vectors[1]);
    }

    #[test]
    fn fingerprint_changes_with_label_and_dim() {
        assert_ne!(fingerprint_for("a", 16), fingerprint_for("b", 16));
        assert_ne!(fingerprint_for("a", 16), fingerprint_for("a", 32));
    }

    #[test]
    fn cpu_preference_reports_no_accelerator() {
        // Guard the process-global env mutation so parallel tests don't race.
        let prev = std::env::var(ACCELERATOR_ENV).ok();
        unsafe { std::env::set_var(ACCELERATOR_ENV, "cpu") };
        assert!(!accelerator_available());
        match prev {
            Some(value) => unsafe { std::env::set_var(ACCELERATOR_ENV, value) },
            None => unsafe { std::env::remove_var(ACCELERATOR_ENV) },
        }
    }
}
