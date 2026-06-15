//! Embedding and reranking engines.
//!
//! `Embedder`/`Reranker` are the seams the indexer and query pipeline depend
//! on; production impls wrap `gte-rs` ONNX pipelines, and deterministic fakes
//! back the model-free tests. Model files resolve from env-pointed local
//! directories first (fine-tune escape hatch), then the HF hub cache.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use sha2::{Digest, Sha256};

use super::keys::l2_normalize;
use super::{MAX_SEQ_TOKENS, PARENT_ALPHA, PASSAGE_PREFIX, QUERY_PREFIX, REPRESENTATION_KIND};

/// Texts embedded per ONNX call; inputs are padded to the longest in a batch,
/// so attention memory scales with `items * longest^2`. The scheduler packs
/// batches under that quadratic cost (see [`EmbedBatch`]); this cap only
/// bounds how many short texts share a call.
const EMBED_BATCH: usize = 16;

/// Query/document pairs scored per ONNX call.
const RERANK_BATCH: usize = 8;

const ACCELERATOR_ENV: &str = "BIFROST_ACCELERATOR";
const CUDA_DEVICES_ENV: &str = "BIFROST_CUDA_DEVICES";
const CUDA_VISIBLE_DEVICES_ENV: &str = "CUDA_VISIBLE_DEVICES";
#[cfg(feature = "nlp-coreml")]
const COREML_ANE_ONLY_ENV: &str = "BIFROST_COREML_ANE_ONLY";
const EMBED_BATCH_MAX_ITEMS_ENV: &str = "BIFROST_EMBED_BATCH_MAX_ITEMS";
const EMBED_BATCH_MAX_TOKENS_ENV: &str = "BIFROST_EMBED_BATCH_MAX_TOKENS";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceleratorPreference {
    Auto,
    Cpu,
    Cuda,
    CoreMl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeTarget {
    Cpu,
    Cuda { device_id: i32 },
    CoreMl,
}

impl RuntimeTarget {
    fn label(self) -> String {
        match self {
            RuntimeTarget::Cpu => "cpu".to_string(),
            RuntimeTarget::Cuda { device_id } => format!("cuda:{device_id}"),
            RuntimeTarget::CoreMl => "coreml".to_string(),
        }
    }
}

#[derive(Clone)]
struct EmbedJob {
    original_index: usize,
    text: String,
    token_count: usize,
}

#[derive(Clone)]
struct EmbedBatch {
    jobs: Vec<EmbedJob>,
    /// Longest sequence in the batch; padding makes every item this long.
    longest: usize,
}

impl EmbedBatch {
    fn new(job: EmbedJob) -> Self {
        Self {
            longest: job.token_count,
            jobs: vec![job],
        }
    }

    /// Padded attention cost if `job` joins: per layer the score matrix is
    /// `items * longest^2`, so that product is what bounds peak memory — not
    /// the summed token count, which lets one long item drag a batch of short
    /// ones up to a multi-GB padded shape.
    fn cost_with(&self, job: &EmbedJob) -> usize {
        let longest = self.longest.max(job.token_count);
        (self.jobs.len() + 1).saturating_mul(longest.saturating_mul(longest))
    }

    fn can_accept(&self, job: &EmbedJob, max_items: usize, max_cost: usize) -> bool {
        self.jobs.len() < max_items && self.cost_with(job) <= max_cost
    }

    fn push(&mut self, job: EmbedJob) {
        self.longest = self.longest.max(job.token_count);
        self.jobs.push(job);
    }
}

/// Locally resolved model files ready to load.
#[derive(Clone)]
pub struct ResolvedModel {
    pub tokenizer: PathBuf,
    pub model: PathBuf,
    /// Stable identity for fingerprinting (repo id + file, or local dir path).
    pub label: String,
}

/// True when the CUDA execution provider can actually run. Always false
/// without the `nlp-gpu` feature (the CPU onnxruntime binary has no CUDA EP).
pub fn gpu_available() -> bool {
    cuda_available()
}

fn cuda_available() -> bool {
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

fn coreml_available() -> bool {
    #[cfg(feature = "nlp-coreml")]
    {
        use ort::execution_providers::{CoreMLExecutionProvider, ExecutionProvider};
        CoreMLExecutionProvider::default()
            .is_available()
            .unwrap_or(false)
    }
    #[cfg(not(feature = "nlp-coreml"))]
    {
        false
    }
}

fn parse_accelerator_preference() -> Result<AcceleratorPreference, String> {
    match std::env::var(ACCELERATOR_ENV)
        .unwrap_or_else(|_| "auto".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "auto" => Ok(AcceleratorPreference::Auto),
        "cpu" => Ok(AcceleratorPreference::Cpu),
        "cuda" => Ok(AcceleratorPreference::Cuda),
        "coreml" | "core-ml" => Ok(AcceleratorPreference::CoreMl),
        other => Err(format!(
            "{ACCELERATOR_ENV} must be one of auto, cpu, cuda, coreml; got {other}"
        )),
    }
}

#[cfg(feature = "nlp-coreml")]
fn parse_bool_env(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES") | Ok("on") | Ok("ON")
    )
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn parse_cuda_devices(
    cuda_devices: Option<&str>,
    cuda_visible_devices: Option<&str>,
    legacy_device: Option<&str>,
) -> Result<Vec<i32>, String> {
    let mut explicit_auto = false;
    if let Some(devices) = cuda_devices {
        let trimmed = devices.trim();
        if !trimmed.eq_ignore_ascii_case("auto") {
            let mut parsed = Vec::new();
            for raw in trimmed.split(',') {
                let device = raw.trim();
                if device.is_empty() {
                    continue;
                }
                parsed.push(device.parse::<i32>().map_err(|err| {
                    format!("invalid {CUDA_DEVICES_ENV} entry `{device}`: {err}")
                })?);
            }
            if parsed.is_empty() {
                return Err(format!("{CUDA_DEVICES_ENV} did not contain any device ids"));
            }
            return Ok(parsed);
        }
        explicit_auto = true;
    }

    if !explicit_auto && let Some(legacy) = legacy_device {
        let trimmed = legacy.trim();
        if !trimmed.is_empty() {
            return Ok(vec![trimmed.parse::<i32>().map_err(|err| {
                format!("invalid {CUDA_DEVICE_ENV} value `{trimmed}`: {err}")
            })?]);
        }
    }

    if let Some(visible) = cuda_visible_devices {
        let trimmed = visible.trim();
        if !trimmed.is_empty() && trimmed != "-1" {
            let count = trimmed
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .count();
            if count > 0 {
                return Ok((0..count as i32).collect());
            }
        }
    }

    Ok(vec![0])
}

fn selected_embedding_targets() -> Result<Vec<RuntimeTarget>, String> {
    match parse_accelerator_preference()? {
        AcceleratorPreference::Cpu => Ok(vec![RuntimeTarget::Cpu]),
        AcceleratorPreference::Cuda => {
            if !cuda_available() {
                return Err("CUDA execution provider is not available".to_string());
            }
            parse_cuda_devices(
                std::env::var(CUDA_DEVICES_ENV).ok().as_deref(),
                std::env::var(CUDA_VISIBLE_DEVICES_ENV).ok().as_deref(),
                std::env::var(CUDA_DEVICE_ENV).ok().as_deref(),
            )
            .map(|devices| {
                devices
                    .into_iter()
                    .map(|device_id| RuntimeTarget::Cuda { device_id })
                    .collect()
            })
        }
        AcceleratorPreference::CoreMl => {
            if !coreml_available() {
                return Err("CoreML execution provider is not available".to_string());
            }
            Ok(vec![RuntimeTarget::CoreMl])
        }
        AcceleratorPreference::Auto => {
            if cuda_available() {
                return parse_cuda_devices(
                    std::env::var(CUDA_DEVICES_ENV).ok().as_deref(),
                    std::env::var(CUDA_VISIBLE_DEVICES_ENV).ok().as_deref(),
                    std::env::var(CUDA_DEVICE_ENV).ok().as_deref(),
                )
                .map(|devices| {
                    devices
                        .into_iter()
                        .map(|device_id| RuntimeTarget::Cuda { device_id })
                        .collect()
                });
            }
            if coreml_available() {
                return Ok(vec![RuntimeTarget::CoreMl]);
            }
            Ok(vec![RuntimeTarget::Cpu])
        }
    }
}

fn selected_query_target() -> Result<RuntimeTarget, String> {
    Ok(selected_embedding_targets()?
        .into_iter()
        .next()
        .unwrap_or(RuntimeTarget::Cpu))
}

fn has_accelerated_target() -> bool {
    selected_query_target()
        .map(|target| !matches!(target, RuntimeTarget::Cpu))
        .unwrap_or(false)
}

fn runtime_params_for(target: RuntimeTarget) -> orp::params::RuntimeParameters {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(4);
    let params = orp::params::RuntimeParameters::default().with_threads(threads);
    match target {
        RuntimeTarget::Cpu => params,
        RuntimeTarget::Cuda { device_id } => {
            #[cfg(feature = "nlp-gpu")]
            {
                use ort::execution_providers::CUDAExecutionProvider;
                params.with_execution_providers([CUDAExecutionProvider::default()
                    .with_device_id(device_id)
                    .build()])
            }
            #[cfg(not(feature = "nlp-gpu"))]
            {
                let _ = device_id;
                params
            }
        }
        RuntimeTarget::CoreMl => {
            #[cfg(feature = "nlp-coreml")]
            {
                use ort::execution_providers::CoreMLExecutionProvider;
                let mut provider = CoreMLExecutionProvider::default();
                if parse_bool_env(COREML_ANE_ONLY_ENV) {
                    provider = provider.with_ane_only();
                }
                params.with_execution_providers([provider.build()])
            }
            #[cfg(not(feature = "nlp-coreml"))]
            {
                params
            }
        }
    }
}

/// Prefer a numerically-equivalent `<stem>.bifrost-opt.onnx` sibling produced
/// by `scripts/optimize_onnx_attention.py` (un-tiled attention masks, ~2x
/// lower peak inference memory at long sequence lengths). Callers keep the
/// original variant in the label so cached vectors stay valid.
///
/// FIXME: delete once the fine-tuned model replaces the granite placeholder.
/// This only exists so profiling against the stock hub export runs on the
/// rewritten graph; the FT export pipeline should emit `key_padding_mask`
/// attention directly (or run the script post-export), making this step moot.
/// It must NOT emit a `(batch, 1, seq, seq)` broadcast attention_bias: the
/// ONNX Runtime 1.20 CPU MHA kernel bundled by ort 2.0.0-rc.9 misindexes that
/// shape for batches > 1 (OOB reads — garbage embeddings or SIGSEGV).
fn prefer_optimized_sibling(model: PathBuf) -> PathBuf {
    let Some(stem) = model.file_stem().and_then(|stem| stem.to_str()) else {
        return model;
    };
    let optimized = model.with_file_name(format!("{stem}.bifrost-opt.onnx"));
    if optimized.is_file() {
        optimized
    } else {
        model
    }
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
        model: prefer_optimized_sibling(model),
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
        model: prefer_optimized_sibling(model),
        label: format!("{repo_id}/{variant}"),
    })
}

pub fn resolve_embed_model() -> Result<ResolvedModel, String> {
    if let Ok(dir) = std::env::var(EMBED_MODEL_DIR_ENV) {
        return resolve_local_dir(Path::new(&dir));
    }
    let repo_id =
        std::env::var(EMBED_MODEL_ID_ENV).unwrap_or_else(|_| DEFAULT_EMBED_MODEL_ID.to_string());
    if has_accelerated_target() {
        // gte-rs 0.9.1 extracts output tensors as f32, so fp16 exports are
        // not usable; full precision is fine on accelerators.
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
    if has_accelerated_target() {
        resolve_hf(&repo_id, "onnx/model.onnx")
    } else {
        resolve_hf(&repo_id, "onnx/model_int8.onnx")
    }
}

pub fn load_production_embedder(resolved: &ResolvedModel) -> Result<Arc<dyn Embedder>, String> {
    let targets = selected_embedding_targets()?;
    if targets.len() == 1 && matches!(targets[0], RuntimeTarget::Cpu) {
        return Ok(Arc::new(GteEmbedder::load_for_target(
            resolved, targets[0],
        )?));
    }

    let mut workers = Vec::with_capacity(targets.len());
    for target in targets {
        workers
            .push(Arc::new(GteEmbedder::load_for_target(resolved, target)?) as Arc<dyn Embedder>);
    }
    Ok(Arc::new(ScheduledEmbedder::new(workers)))
}

pub fn load_production_reranker(resolved: &ResolvedModel) -> Result<Arc<dyn Reranker>, String> {
    let target = selected_query_target()?;
    Ok(Arc::new(GteReranker::load_for_target(resolved, target)?))
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
        Self::load_for_target(resolved, selected_query_target()?)
    }

    fn load_for_target(resolved: &ResolvedModel, target: RuntimeTarget) -> Result<Self, String> {
        let params = gte::params::Parameters::default().with_max_length(Some(MAX_SEQ_TOKENS));
        let pipeline =
            gte::embed::pipeline::TextEmbeddingPipeline::new(&resolved.tokenizer, &params)
                .map_err(|err| format!("embedding pipeline init failed: {err}"))?;
        let model =
            orp::model::Model::new(&resolved.model, runtime_params_for(target)).map_err(|err| {
                format!(
                    "embedding model load failed ({} on {}): {err}",
                    resolved.label,
                    target.label()
                )
            })?;
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

struct ScheduledEmbedder {
    workers: Vec<Arc<dyn Embedder>>,
    max_items: usize,
    /// Quadratic batch budget in `items * longest^2` units; defaults to the
    /// cost of a single max-length sequence, so one 8k chunk runs alone while
    /// 2k chunks batch 4 at a time and short chunks fill `max_items`.
    max_cost: usize,
}

impl ScheduledEmbedder {
    fn new(workers: Vec<Arc<dyn Embedder>>) -> Self {
        let budget_tokens = parse_usize_env(EMBED_BATCH_MAX_TOKENS_ENV, MAX_SEQ_TOKENS);
        Self::with_limits(
            workers,
            parse_usize_env(EMBED_BATCH_MAX_ITEMS_ENV, EMBED_BATCH),
            budget_tokens.saturating_mul(budget_tokens),
        )
    }

    fn with_limits(workers: Vec<Arc<dyn Embedder>>, max_items: usize, max_cost: usize) -> Self {
        Self {
            workers,
            max_items,
            max_cost,
        }
    }

    fn embed_texts(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let jobs: Vec<EmbedJob> = texts
            .iter()
            .enumerate()
            .map(|(index, text)| EmbedJob {
                original_index: index,
                text: text.clone(),
                // The pipeline truncates to MAX_SEQ_TOKENS, so longer counts
                // (including the tokenizer-error usize::MAX sentinel) cost the
                // same as a max-length sequence.
                token_count: self.count_tokens(text).min(MAX_SEQ_TOKENS),
            })
            .collect();
        let batches = pack_embed_jobs(jobs, self.max_items, self.max_cost);
        let queue = Arc::new(Mutex::new(VecDeque::from(batches)));
        let results = Arc::new(Mutex::new(vec![None; texts.len()]));
        let error = Arc::new(Mutex::new(None::<String>));

        thread::scope(|scope| {
            for worker in &self.workers {
                let queue = Arc::clone(&queue);
                let results = Arc::clone(&results);
                let error = Arc::clone(&error);
                scope.spawn(move || {
                    loop {
                        if error
                            .lock()
                            .expect("scheduler error mutex poisoned")
                            .is_some()
                        {
                            return;
                        }
                        let Some(batch) = queue
                            .lock()
                            .expect("scheduler queue mutex poisoned")
                            .pop_front()
                        else {
                            return;
                        };
                        let batch_texts: Vec<&str> =
                            batch.jobs.iter().map(|job| job.text.as_str()).collect();
                        let vectors = match worker.embed_passages(&batch_texts) {
                            Ok(vectors) => vectors,
                            Err(err) => {
                                *error.lock().expect("scheduler error mutex poisoned") = Some(err);
                                return;
                            }
                        };
                        if vectors.len() != batch.jobs.len() {
                            *error.lock().expect("scheduler error mutex poisoned") = Some(format!(
                                "embedding worker returned {} vectors for {} texts",
                                vectors.len(),
                                batch.jobs.len()
                            ));
                            return;
                        }
                        let mut results = results.lock().expect("scheduler results mutex poisoned");
                        for (job, vector) in batch.jobs.iter().zip(vectors) {
                            results[job.original_index] = Some(vector);
                        }
                    }
                });
            }
        });

        if let Some(err) = error.lock().expect("scheduler error mutex poisoned").take() {
            return Err(err);
        }
        let results = Arc::try_unwrap(results)
            .map_err(|_| "embedding scheduler results still shared".to_string())?
            .into_inner()
            .map_err(|_| "embedding scheduler results mutex poisoned".to_string())?;
        results
            .into_iter()
            .map(|maybe_vector| {
                maybe_vector.ok_or_else(|| "embedding scheduler missing vector".to_string())
            })
            .collect()
    }
}

impl Embedder for ScheduledEmbedder {
    fn dim(&self) -> usize {
        self.workers[0].dim()
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        let owned: Vec<String> = texts.iter().map(|text| (*text).to_string()).collect();
        self.embed_texts(&owned)
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

fn pack_embed_jobs(mut jobs: Vec<EmbedJob>, max_items: usize, max_cost: usize) -> Vec<EmbedBatch> {
    let max_items = max_items.max(1);
    let max_cost = max_cost.max(1);
    jobs.sort_by(|left, right| {
        right
            .token_count
            .cmp(&left.token_count)
            .then_with(|| left.original_index.cmp(&right.original_index))
    });
    let mut batches: Vec<EmbedBatch> = Vec::new();
    for job in jobs {
        let Some(batch) = batches
            .iter_mut()
            .find(|batch| batch.can_accept(&job, max_items, max_cost))
        else {
            batches.push(EmbedBatch::new(job));
            continue;
        };
        batch.push(job);
    }
    batches
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
        Self::load_for_target(resolved, selected_query_target()?)
    }

    fn load_for_target(resolved: &ResolvedModel, target: RuntimeTarget) -> Result<Self, String> {
        let params = gte::params::Parameters::default()
            .with_max_length(Some(MAX_SEQ_TOKENS))
            .with_sigmoid(true);
        let pipeline = gte::rerank::pipeline::RerankingPipeline::new(&resolved.tokenizer, &params)
            .map_err(|err| format!("rerank pipeline init failed: {err}"))?;
        let model =
            orp::model::Model::new(&resolved.model, runtime_params_for(target)).map_err(|err| {
                format!(
                    "rerank model load failed ({} on {}): {err}",
                    resolved.label,
                    target.label()
                )
            })?;
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
    use std::sync::Arc;
    use std::time::Duration;

    struct WorkerFakeEmbedder {
        id: f32,
        delay: Duration,
        calls: AtomicUsize,
        dim: usize,
    }

    impl WorkerFakeEmbedder {
        fn new(id: f32, delay: Duration) -> Self {
            Self {
                id,
                delay,
                calls: AtomicUsize::new(0),
                dim: 2,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Embedder for WorkerFakeEmbedder {
        fn dim(&self) -> usize {
            self.dim
        }

        fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            Ok(texts
                .iter()
                .map(|text| vec![self.id, text.parse::<f32>().unwrap_or(0.0)])
                .collect())
        }

        fn embed_query(&self, text: &str) -> Result<Vec<f32>, String> {
            Ok(vec![self.id, text.parse::<f32>().unwrap_or(0.0)])
        }

        fn count_tokens(&self, text: &str) -> usize {
            text.parse::<usize>().unwrap_or(1)
        }

        fn fingerprint(&self) -> String {
            format!("worker-fake:{}", self.id)
        }
    }

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

    #[test]
    fn cuda_device_parsing_honors_explicit_list() {
        assert_eq!(
            parse_cuda_devices(Some("2, 4"), Some("7,8,9"), Some("1")).unwrap(),
            vec![2, 4]
        );
    }

    #[test]
    fn cuda_device_parsing_uses_legacy_single_device() {
        assert_eq!(
            parse_cuda_devices(None, Some("7,8,9"), Some("3")).unwrap(),
            vec![3]
        );
    }

    #[test]
    fn cuda_device_auto_maps_visible_devices_to_logical_ids() {
        assert_eq!(
            parse_cuda_devices(Some("auto"), Some("7,8,9"), None).unwrap(),
            vec![0, 1, 2]
        );
        assert_eq!(
            parse_cuda_devices(Some("auto"), Some("7,8,9"), Some("3")).unwrap(),
            vec![0, 1, 2]
        );
        assert_eq!(parse_cuda_devices(None, Some("-1"), None).unwrap(), vec![0]);
    }

    fn jobs_with_token_counts(token_counts: &[usize]) -> Vec<EmbedJob> {
        token_counts
            .iter()
            .enumerate()
            .map(|(index, &token_count)| EmbedJob {
                original_index: index,
                text: token_count.to_string(),
                token_count,
            })
            .collect()
    }

    fn batch_token_counts(batches: &[EmbedBatch]) -> Vec<Vec<usize>> {
        batches
            .iter()
            .map(|batch| batch.jobs.iter().map(|job| job.token_count).collect())
            .collect()
    }

    #[test]
    fn pack_embed_jobs_groups_similar_lengths_under_cost() {
        let jobs = jobs_with_token_counts(&[100, 95, 10, 9, 8]);

        // Budget of two 100-token sequences: the long pair shares a batch,
        // the short jobs pair off separately instead of padding up to 100.
        let batches = pack_embed_jobs(jobs, 2, 2 * 100 * 100);

        assert_eq!(
            batch_token_counts(&batches),
            vec![vec![100, 95], vec![10, 9], vec![8]]
        );
    }

    #[test]
    fn pack_embed_jobs_runs_long_item_alone_under_cost() {
        let jobs = jobs_with_token_counts(&[100, 10, 9, 8]);

        // Budget of one 100-token sequence: padding any short job up to 100
        // would double the cost, so the long job runs solo and the short jobs
        // batch together well under budget.
        let batches = pack_embed_jobs(jobs, 4, 100 * 100);

        assert_eq!(
            batch_token_counts(&batches),
            vec![vec![100], vec![10, 9, 8]]
        );
    }

    #[test]
    fn scheduled_embedder_preserves_input_order() {
        let left = Arc::new(WorkerFakeEmbedder::new(1.0, Duration::from_millis(5)));
        let right = Arc::new(WorkerFakeEmbedder::new(2.0, Duration::ZERO));
        let embedder = ScheduledEmbedder::with_limits(
            vec![left as Arc<dyn Embedder>, right as Arc<dyn Embedder>],
            1,
            100,
        );

        let vectors = embedder.embed_passages(&["0", "1", "2", "3"]).unwrap();

        assert_eq!(vectors.len(), 4);
        assert_eq!(vectors[0][1], 0.0);
        assert_eq!(vectors[1][1], 1.0);
        assert_eq!(vectors[2][1], 2.0);
        assert_eq!(vectors[3][1], 3.0);
    }

    #[test]
    fn scheduled_embedder_lets_faster_workers_pull_more_batches() {
        let slow = Arc::new(WorkerFakeEmbedder::new(1.0, Duration::from_millis(40)));
        let fast = Arc::new(WorkerFakeEmbedder::new(2.0, Duration::ZERO));
        let embedder = ScheduledEmbedder::with_limits(
            vec![
                slow.clone() as Arc<dyn Embedder>,
                fast.clone() as Arc<dyn Embedder>,
            ],
            1,
            100,
        );

        let inputs: Vec<String> = (0..12).map(|index| index.to_string()).collect();
        let refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
        let vectors = embedder.embed_passages(&refs).unwrap();

        assert_eq!(vectors.len(), inputs.len());
        assert!(
            fast.calls() > slow.calls(),
            "fast worker should pull more queue pages; slow={}, fast={}",
            slow.calls(),
            fast.calls()
        );
    }
}
