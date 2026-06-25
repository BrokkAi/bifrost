//! Embedding engine.
//!
//! `Embedder` is the seam the indexer and query pipeline depend on; the
//! production impl ([`super::voyage::VoyageEmbedder`]) runs voyageai/voyage-4-nano
//! through Candle, and a deterministic fake backs the model-free tests. Model files
//! resolve from an env-pointed local directory first (fine-tune escape hatch), then
//! the HF hub cache. Accelerator selection (CUDA / Metal / CPU) goes through Candle's
//! own device backends.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use candle_core::Device;
use sha2::{Digest, Sha256};

use super::keys::l2_normalize;
use super::voyage::VoyageEmbedder;
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
const CUDA_DEVICE_ENV: &str = "BIFROST_CUDA_DEVICE";

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

fn cuda_ordinal() -> usize {
    std::env::var(CUDA_DEVICE_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// The Candle device the embedder will run on, honoring `BIFROST_ACCELERATOR`.
/// `Auto` prefers CUDA, then Metal, then CPU.
pub fn select_device() -> Result<Device, String> {
    match accelerator_preference() {
        AcceleratorPreference::Cpu => Ok(Device::Cpu),
        AcceleratorPreference::Cuda => Device::new_cuda(cuda_ordinal())
            .map_err(|err| format!("CUDA device unavailable: {err}")),
        AcceleratorPreference::Metal => {
            Device::new_metal(0).map_err(|err| format!("Metal device unavailable: {err}"))
        }
        AcceleratorPreference::Auto => {
            if let Ok(device) = Device::new_cuda(cuda_ordinal()) {
                return Ok(device);
            }
            if let Ok(device) = Device::new_metal(0) {
                return Ok(device);
            }
            Ok(Device::Cpu)
        }
    }
}

/// Whether a CUDA or Metal accelerator is actually usable under the current
/// preference. Drives whether `semantic_search` is offered (an explicit `cpu`
/// preference reports `false` — it must be force-enabled).
pub fn accelerator_available() -> bool {
    match accelerator_preference() {
        AcceleratorPreference::Cpu => false,
        AcceleratorPreference::Cuda => Device::new_cuda(cuda_ordinal()).is_ok(),
        AcceleratorPreference::Metal => Device::new_metal(0).is_ok(),
        AcceleratorPreference::Auto => {
            Device::new_cuda(cuda_ordinal()).is_ok() || Device::new_metal(0).is_ok()
        }
    }
}

fn embed_repo_id() -> String {
    std::env::var(EMBED_MODEL_ID_ENV).unwrap_or_else(|_| DEFAULT_EMBED_MODEL_ID.to_string())
}

/// Directory holding the model's `config.json`, `tokenizer.json`, and
/// `model.safetensors`. Resolves from `BIFROST_EMBED_MODEL_DIR` first, else
/// downloads (or reuses the cache of) the HF repo.
fn resolve_embed_model_dir() -> Result<PathBuf, String> {
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
    let device = select_device()?;
    let dir = resolve_embed_model_dir()?;
    Ok(Arc::new(VoyageEmbedder::load(
        &dir,
        device,
        embed_repo_id(),
    )?))
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
        assert!(matches!(select_device(), Ok(Device::Cpu)));
        match prev {
            Some(value) => unsafe { std::env::set_var(ACCELERATOR_ENV, value) },
            None => unsafe { std::env::remove_var(ACCELERATOR_ENV) },
        }
    }
}
