//! Embedding and reranking engines.
//!
//! `Embedder`/`Reranker` are the seams the indexer and query pipeline depend
//! on; production impls wrap `gte-rs` ONNX pipelines, and deterministic fakes
//! back the model-free tests. Model files resolve from env-pointed local
//! directories first (fine-tune escape hatch), then the HF hub cache.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use super::keys::l2_normalize;
use super::{MAX_SEQ_TOKENS, PARENT_ALPHA, PASSAGE_PREFIX, QUERY_PREFIX, REPRESENTATION_KIND};

/// Texts embedded per ONNX call; inputs are padded to the longest in a batch,
/// so this bounds peak activation memory with 8k-token chunks.
const EMBED_BATCH: usize = 16;

/// Query/document pairs scored per ONNX call.
const RERANK_BATCH: usize = 8;

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

pub trait Reranker: Send + Sync {
    /// Cross-encoder relevance of each doc to the query, higher is better.
    fn score_pairs(&self, query: &str, docs: &[String]) -> Result<Vec<f32>, String>;
}

/// Fingerprint recipe shared by all embedders: model label + dimensionality +
/// the exact prefix strings + vector representation contract.
fn fingerprint_for(label: &str, dim: usize) -> String {
    let mut hasher = Sha256::new();
    for part in [
        label,
        &dim.to_string(),
        QUERY_PREFIX,
        PASSAGE_PREFIX,
        REPRESENTATION_KIND,
        &format!("alpha={PARENT_ALPHA}"),
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

pub const DEFAULT_EMBED_MODEL_ID: &str = "onnx-community/granite-embedding-small-english-r2-ONNX";
pub const DEFAULT_RERANK_MODEL_ID: &str = "Alibaba-NLP/gte-reranker-modernbert-base";

pub const EMBED_MODEL_DIR_ENV: &str = "BIFROST_EMBED_MODEL_DIR";
pub const RERANK_MODEL_DIR_ENV: &str = "BIFROST_RERANK_MODEL_DIR";
pub const EMBED_MODEL_ID_ENV: &str = "BIFROST_EMBED_MODEL_ID";
pub const RERANK_MODEL_ID_ENV: &str = "BIFROST_RERANK_MODEL_ID";
pub const CUDA_DEVICE_ENV: &str = "BIFROST_CUDA_DEVICE";

/// Locally resolved model files ready to load.
pub struct ResolvedModel {
    pub tokenizer: PathBuf,
    pub model: PathBuf,
    /// Stable identity for fingerprinting (repo id + file, or local dir path).
    pub label: String,
}

/// True when the CUDA execution provider can actually run. Always false
/// without the `nlp-gpu` feature (the CPU onnxruntime binary has no CUDA EP).
pub fn gpu_available() -> bool {
    #[cfg(feature = "nlp-gpu")]
    {
        use ort::execution_providers::{CUDAExecutionProvider, ExecutionProvider};
        CUDAExecutionProvider::default()
            .is_available()
            .unwrap_or(false)
    }
    #[cfg(not(feature = "nlp-gpu"))]
    {
        false
    }
}

fn runtime_params() -> orp::params::RuntimeParameters {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(4);
    let params = orp::params::RuntimeParameters::default().with_threads(threads);
    #[cfg(feature = "nlp-gpu")]
    if gpu_available() {
        use ort::execution_providers::CUDAExecutionProvider;
        let device = std::env::var(CUDA_DEVICE_ENV)
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);
        return params.with_execution_providers([CUDAExecutionProvider::default()
            .with_device_id(device)
            .build()]);
    }
    params
}

/// Resolve a model from a local directory containing `tokenizer.json` and
/// `model.onnx` (single-file or with an external-data sibling).
fn resolve_local_dir(dir: &Path) -> Result<ResolvedModel, String> {
    let tokenizer = dir.join("tokenizer.json");
    let model = dir.join("model.onnx");
    for required in [&tokenizer, &model] {
        if !required.is_file() {
            return Err(format!(
                "model dir {} is missing {}",
                dir.display(),
                required.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
    }
    Ok(ResolvedModel {
        tokenizer,
        model,
        label: format!("local:{}", dir.display()),
    })
}

/// Fetch `repo_id`'s tokenizer + the chosen onnx variant (and its
/// `.onnx_data` external-data sibling, when one exists) into the HF cache.
fn resolve_hf(repo_id: &str, variant: &str) -> Result<ResolvedModel, String> {
    let api = hf_hub::api::sync::Api::new().map_err(|err| format!("hf-hub init failed: {err}"))?;
    let repo = api.model(repo_id.to_string());
    let tokenizer = repo
        .get("tokenizer.json")
        .map_err(|err| format!("download {repo_id}/tokenizer.json failed: {err}"))?;
    let model = repo
        .get(variant)
        .map_err(|err| format!("download {repo_id}/{variant} failed: {err}"))?;
    // External-data exports must have the sibling in the same snapshot dir;
    // single-file exports simply don't have one.
    let _ = repo.get(&format!("{variant}_data"));
    Ok(ResolvedModel {
        tokenizer,
        model,
        label: format!("{repo_id}/{variant}"),
    })
}

pub fn resolve_embed_model() -> Result<ResolvedModel, String> {
    if let Ok(dir) = std::env::var(EMBED_MODEL_DIR_ENV) {
        return resolve_local_dir(Path::new(&dir));
    }
    let repo_id =
        std::env::var(EMBED_MODEL_ID_ENV).unwrap_or_else(|_| DEFAULT_EMBED_MODEL_ID.to_string());
    if gpu_available() {
        // gte-rs 0.9.1 extracts output tensors as f32, so fp16 exports are
        // not usable; full precision is fine on GPU.
        resolve_hf(&repo_id, "onnx/model.onnx")
    } else {
        resolve_hf(&repo_id, "onnx/model_quantized.onnx")
    }
}

pub fn resolve_rerank_model() -> Result<ResolvedModel, String> {
    if let Ok(dir) = std::env::var(RERANK_MODEL_DIR_ENV) {
        return resolve_local_dir(Path::new(&dir));
    }
    let repo_id =
        std::env::var(RERANK_MODEL_ID_ENV).unwrap_or_else(|_| DEFAULT_RERANK_MODEL_ID.to_string());
    if gpu_available() {
        resolve_hf(&repo_id, "onnx/model.onnx")
    } else {
        resolve_hf(&repo_id, "onnx/model_int8.onnx")
    }
}

// ---------------------------------------------------------------------------
// gte-rs implementations
// ---------------------------------------------------------------------------

pub struct GteEmbedder {
    model: orp::model::Model,
    pipeline: gte::embed::pipeline::TextEmbeddingPipeline,
    params: gte::params::Parameters,
    token_counter: tokenizers::Tokenizer,
    dim: usize,
    label: String,
}

impl GteEmbedder {
    pub fn load(resolved: &ResolvedModel) -> Result<Self, String> {
        let params = gte::params::Parameters::default().with_max_length(Some(MAX_SEQ_TOKENS));
        let pipeline =
            gte::embed::pipeline::TextEmbeddingPipeline::new(&resolved.tokenizer, &params)
                .map_err(|err| format!("embedding pipeline init failed: {err}"))?;
        let model = orp::model::Model::new(&resolved.model, runtime_params())
            .map_err(|err| format!("embedding model load failed ({}): {err}", resolved.label))?;
        let token_counter = tokenizers::Tokenizer::from_file(&resolved.tokenizer)
            .map_err(|err| format!("tokenizer load failed: {err}"))?;
        let mut embedder = Self {
            model,
            pipeline,
            params,
            token_counter,
            dim: 0,
            label: resolved.label.clone(),
        };
        // One probe inference both validates the model and records the
        // embedding dimensionality for the fingerprint.
        let probe = embedder.embed_raw(&["dimension probe".to_string()])?;
        embedder.dim = probe.first().map(Vec::len).unwrap_or(0);
        if embedder.dim == 0 {
            return Err(format!(
                "embedding model {} returned no output",
                embedder.label
            ));
        }
        Ok(embedder)
    }

    /// Embed pre-prefixed texts in memory-bounded batches.
    fn embed_raw(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let mut out = Vec::with_capacity(texts.len());
        for batch in texts.chunks(EMBED_BATCH) {
            let input = gte::embed::input::TextInput::new(batch.to_vec());
            let embeddings = self
                .model
                .inference(input, &self.pipeline, &self.params)
                .map_err(|err| format!("embedding inference failed: {err}"))?;
            for row in 0..embeddings.len() {
                let mut vector = embeddings.embeddings(row).to_vec();
                l2_normalize(&mut vector);
                out.push(vector);
            }
        }
        Ok(out)
    }
}

impl Embedder for GteEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        let prefixed: Vec<String> = texts
            .iter()
            .map(|text| format!("{PASSAGE_PREFIX}{text}"))
            .collect();
        self.embed_raw(&prefixed)
    }

    fn embed_query(&self, text: &str) -> Result<Vec<f32>, String> {
        let mut vectors = self.embed_raw(&[format!("{QUERY_PREFIX}{text}")])?;
        vectors
            .pop()
            .ok_or_else(|| "embedding model returned no query vector".to_string())
    }

    fn count_tokens(&self, text: &str) -> usize {
        self.token_counter
            .encode(text, false)
            .map(|encoding| encoding.len())
            .unwrap_or(usize::MAX)
    }

    fn fingerprint(&self) -> String {
        fingerprint_for(&self.label, self.dim)
    }
}

pub struct GteReranker {
    model: orp::model::Model,
    pipeline: gte::rerank::pipeline::RerankingPipeline,
    params: gte::params::Parameters,
}

impl GteReranker {
    pub fn load(resolved: &ResolvedModel) -> Result<Self, String> {
        let params = gte::params::Parameters::default()
            .with_max_length(Some(MAX_SEQ_TOKENS))
            .with_sigmoid(true);
        let pipeline = gte::rerank::pipeline::RerankingPipeline::new(&resolved.tokenizer, &params)
            .map_err(|err| format!("rerank pipeline init failed: {err}"))?;
        let model = orp::model::Model::new(&resolved.model, runtime_params())
            .map_err(|err| format!("rerank model load failed ({}): {err}", resolved.label))?;
        Ok(Self {
            model,
            pipeline,
            params,
        })
    }
}

impl Reranker for GteReranker {
    fn score_pairs(&self, query: &str, docs: &[String]) -> Result<Vec<f32>, String> {
        let mut scores = Vec::with_capacity(docs.len());
        for batch in docs.chunks(RERANK_BATCH) {
            let pairs: Vec<(String, String)> = batch
                .iter()
                .map(|doc| (query.to_string(), doc.clone()))
                .collect();
            let input = gte::rerank::input::TextInput::new(pairs);
            let output = self
                .model
                .inference(input, &self.pipeline, &self.params)
                .map_err(|err| format!("rerank inference failed: {err}"))?;
            scores.extend(output.scores.iter().copied());
        }
        Ok(scores)
    }
}

// ---------------------------------------------------------------------------
// Deterministic fakes for model-free tests
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

/// Test-only reranker: score = case-insensitive token overlap with the query.
pub struct FakeOverlapReranker;

impl Reranker for FakeOverlapReranker {
    fn score_pairs(&self, query: &str, docs: &[String]) -> Result<Vec<f32>, String> {
        let query_tokens: Vec<String> =
            query.split_whitespace().map(|t| t.to_lowercase()).collect();
        Ok(docs
            .iter()
            .map(|doc| {
                let doc_lower = doc.to_lowercase();
                query_tokens
                    .iter()
                    .filter(|token| doc_lower.contains(*token))
                    .count() as f32
            })
            .collect())
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
    fn fake_reranker_scores_overlap() {
        let scores = FakeOverlapReranker
            .score_pairs(
                "parse config file",
                &["loads the config file".to_string(), "unrelated".to_string()],
            )
            .unwrap();
        assert!(scores[0] > scores[1]);
    }

    #[test]
    fn fingerprint_changes_with_label_and_dim() {
        assert_ne!(fingerprint_for("a", 16), fingerprint_for("b", 16));
        assert_ne!(fingerprint_for("a", 16), fingerprint_for("a", 32));
    }
}
