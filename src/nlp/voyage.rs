//! voyageai/voyage-4-nano embedder, served via Candle.
//!
//! The model is a Qwen3 body (12 layers, hidden 1024, GQA 16q/8kv, head_dim 128,
//! per-head q/k RMSNorm, RoPE theta 1e6, SwiGLU MLP) made **bidirectional** — every
//! layer attends with a padding mask only, no causal triangle — followed by a
//! bias-free `linear` head that projects each token 1024 -> 2048. SentenceTransformer
//! then mean-pools (prompt tokens included) and L2-normalizes; deployment MRL-truncates
//! to 512 and re-normalizes.
//!
//! DIMENSION TRAP: the embedding dim is 2048, NOT hidden 1024 — the `linear` head is
//! what makes it 2048. Serving the body without the head yields silently-wrong vectors.
//! The truncated 512-slice must be re-normalized (a sliced unit vector is not unit).
//! See the parity reference: brokkbench/localizer tools/native_localizer_helper.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use candle_core::{DType, Device, Tensor};
use candle_nn::{Embedding, Linear, Module, RmsNorm, VarBuilder};
use tokenizers::Tokenizer;

use super::engine::Embedder;
use super::{MAX_SEQ_TOKENS, PASSAGE_PREFIX, QUERY_PREFIX};

/// Native projected dimension (after the `linear` head), before MRL truncation.
const NATIVE_DIM: usize = 2048;
/// Deployment embedding dimension (matryoshka-prefix truncation of the native 2048).
pub const VOYAGE_OUTPUT_DIM: usize = 512;
/// Padded-token budget per forward pass: `batch_count * longest_seq_in_batch`.
/// Inputs pad to the batch's longest sequence and attention is O(seq^2), so a fixed
/// item count lets one long chunk pad a whole batch up to its length and blow GPU
/// memory into the tens of GB. Capping padded tokens bounds peak memory; a single
/// chunk longer than the budget still runs alone (it can't be split).
const PADDED_TOKEN_BUDGET: usize = MAX_SEQ_TOKENS;
const EMBED_PROFILE_ENV: &str = "BIFROST_EMBED_PROFILE";
const EMBED_DTYPE_ENV: &str = "BIFROST_EMBED_DTYPE";

static FORCE_EMBED_PROFILE: AtomicBool = AtomicBool::new(false);

pub fn enable_embed_profile_logging() {
    FORCE_EMBED_PROFILE.store(true, Ordering::Relaxed);
}

fn embed_profile_enabled() -> bool {
    FORCE_EMBED_PROFILE.load(Ordering::Relaxed)
        || matches!(
            std::env::var(EMBED_PROFILE_ENV).as_deref(),
            Ok("1") | Ok("true") | Ok("on") | Ok("enabled")
        )
}

/// Qwen3 hyper-parameters for voyage-4-nano. Parsed from the model `config.json`;
/// fields not needed by the encoder forward are ignored.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct VoyageConfig {
    pub hidden_size: usize,
    pub intermediate_size: usize,
    pub num_hidden_layers: usize,
    pub num_attention_heads: usize,
    pub num_key_value_heads: usize,
    pub head_dim: usize,
    pub rms_norm_eps: f64,
    pub rope_theta: f64,
    pub vocab_size: usize,
    /// Output dim of the projection head (`num_labels`); the native embedding dim.
    #[serde(default)]
    pub num_labels: usize,
}

struct RotaryEmbedding {
    cos: Tensor,
    sin: Tensor,
}

impl RotaryEmbedding {
    fn new(cfg: &VoyageConfig, device: &Device, dtype: DType) -> candle_core::Result<Self> {
        let dim = cfg.head_dim;
        let max_seq = MAX_SEQ_TOKENS;
        let inv_freq: Vec<f32> = (0..dim / 2)
            .map(|i| 1f32 / (cfg.rope_theta as f32).powf((2 * i) as f32 / dim as f32))
            .collect();
        let inv_freq = Tensor::from_vec(inv_freq, (1, dim / 2), device)?;
        let positions: Vec<f32> = (0..max_seq).map(|p| p as f32).collect();
        let positions = Tensor::from_vec(positions, (max_seq, 1), device)?;
        // (max_seq, dim/2)
        let freqs = positions.matmul(&inv_freq)?;
        Ok(Self {
            cos: freqs.cos()?.to_dtype(dtype)?,
            sin: freqs.sin()?.to_dtype(dtype)?,
        })
    }

    /// Apply rotary embedding to `x` of shape (b, heads, seq, head_dim).
    fn apply(&self, x: &Tensor, seq_len: usize) -> candle_core::Result<Tensor> {
        let cos = self.cos.narrow(0, 0, seq_len)?;
        let sin = self.sin.narrow(0, 0, seq_len)?;
        candle_nn::rotary_emb::rope(&x.contiguous()?, &cos, &sin)
    }
}

struct Attention {
    q_proj: Linear,
    k_proj: Linear,
    v_proj: Linear,
    o_proj: Linear,
    q_norm: RmsNorm,
    k_norm: RmsNorm,
    num_heads: usize,
    num_kv_heads: usize,
    head_dim: usize,
}

impl Attention {
    fn load(cfg: &VoyageConfig, vb: VarBuilder) -> candle_core::Result<Self> {
        let h = cfg.hidden_size;
        let q_out = cfg.num_attention_heads * cfg.head_dim;
        let kv_out = cfg.num_key_value_heads * cfg.head_dim;
        Ok(Self {
            q_proj: candle_nn::linear_no_bias(h, q_out, vb.pp("q_proj"))?,
            k_proj: candle_nn::linear_no_bias(h, kv_out, vb.pp("k_proj"))?,
            v_proj: candle_nn::linear_no_bias(h, kv_out, vb.pp("v_proj"))?,
            o_proj: candle_nn::linear_no_bias(q_out, h, vb.pp("o_proj"))?,
            q_norm: candle_nn::rms_norm(cfg.head_dim, cfg.rms_norm_eps, vb.pp("q_norm"))?,
            k_norm: candle_nn::rms_norm(cfg.head_dim, cfg.rms_norm_eps, vb.pp("k_norm"))?,
            num_heads: cfg.num_attention_heads,
            num_kv_heads: cfg.num_key_value_heads,
            head_dim: cfg.head_dim,
        })
    }

    /// `x`: (b, seq, hidden). `mask`: (b, 1, seq, seq) additive (0 / -inf), bidirectional.
    fn forward(
        &self,
        x: &Tensor,
        mask: &Tensor,
        rotary: &RotaryEmbedding,
    ) -> candle_core::Result<Tensor> {
        let (b, seq, _) = x.dims3()?;
        let q = self.q_proj.forward(x)?;
        let k = self.k_proj.forward(x)?;
        let v = self.v_proj.forward(x)?;

        // (b, seq, heads, head_dim) -> per-head RMSNorm over head_dim -> (b, heads, seq, head_dim)
        let q = q.reshape((b, seq, self.num_heads, self.head_dim))?;
        let k = k.reshape((b, seq, self.num_kv_heads, self.head_dim))?;
        let q = self.q_norm.forward(&q)?.transpose(1, 2)?;
        let k = self.k_norm.forward(&k)?.transpose(1, 2)?;
        let v = v
            .reshape((b, seq, self.num_kv_heads, self.head_dim))?
            .transpose(1, 2)?;

        let q = rotary.apply(&q, seq)?;
        let k = rotary.apply(&k, seq)?;

        // GQA: repeat kv heads to match q heads.
        let rep = self.num_heads / self.num_kv_heads;
        let k = repeat_kv(&k, rep)?;
        let v = repeat_kv(&v, rep)?;

        let scale = 1f64 / (self.head_dim as f64).sqrt();
        let attn = (q.contiguous()?.matmul(&k.transpose(2, 3)?.contiguous()?)? * scale)?;
        let attn = attn.broadcast_add(mask)?;
        let attn = candle_nn::ops::softmax_last_dim(&attn)?;
        let out = attn.matmul(&v.contiguous()?)?; // (b, heads, seq, head_dim)
        let out = out
            .transpose(1, 2)?
            .reshape((b, seq, self.num_heads * self.head_dim))?;
        self.o_proj.forward(&out)
    }
}

fn repeat_kv(x: &Tensor, rep: usize) -> candle_core::Result<Tensor> {
    if rep == 1 {
        return Ok(x.clone());
    }
    let (b, kv, seq, d) = x.dims4()?;
    x.unsqueeze(2)?
        .expand((b, kv, rep, seq, d))?
        .reshape((b, kv * rep, seq, d))
}

struct Mlp {
    gate_proj: Linear,
    up_proj: Linear,
    down_proj: Linear,
}

impl Mlp {
    fn load(cfg: &VoyageConfig, vb: VarBuilder) -> candle_core::Result<Self> {
        let (h, i) = (cfg.hidden_size, cfg.intermediate_size);
        Ok(Self {
            gate_proj: candle_nn::linear_no_bias(h, i, vb.pp("gate_proj"))?,
            up_proj: candle_nn::linear_no_bias(h, i, vb.pp("up_proj"))?,
            down_proj: candle_nn::linear_no_bias(i, h, vb.pp("down_proj"))?,
        })
    }

    fn forward(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        let gate = candle_nn::ops::silu(&self.gate_proj.forward(x)?)?;
        let up = self.up_proj.forward(x)?;
        self.down_proj.forward(&(gate * up)?)
    }
}

struct DecoderLayer {
    input_layernorm: RmsNorm,
    self_attn: Attention,
    post_attention_layernorm: RmsNorm,
    mlp: Mlp,
}

impl DecoderLayer {
    fn load(cfg: &VoyageConfig, vb: VarBuilder) -> candle_core::Result<Self> {
        Ok(Self {
            input_layernorm: candle_nn::rms_norm(
                cfg.hidden_size,
                cfg.rms_norm_eps,
                vb.pp("input_layernorm"),
            )?,
            self_attn: Attention::load(cfg, vb.pp("self_attn"))?,
            post_attention_layernorm: candle_nn::rms_norm(
                cfg.hidden_size,
                cfg.rms_norm_eps,
                vb.pp("post_attention_layernorm"),
            )?,
            mlp: Mlp::load(cfg, vb.pp("mlp"))?,
        })
    }

    fn forward(
        &self,
        x: &Tensor,
        mask: &Tensor,
        rotary: &RotaryEmbedding,
    ) -> candle_core::Result<Tensor> {
        let residual = x;
        let h = self.input_layernorm.forward(x)?;
        let h = self.self_attn.forward(&h, mask, rotary)?;
        let x = (residual + h)?;
        let residual = &x;
        let h = self.post_attention_layernorm.forward(&x)?;
        let h = self.mlp.forward(&h)?;
        residual + h
    }
}

/// The Qwen3-bidirectional encoder + projection head. Outputs per-token vectors of
/// dimension `num_labels` (2048).
struct Qwen3BidirectionalModel {
    embed_tokens: Embedding,
    layers: Vec<DecoderLayer>,
    norm: RmsNorm,
    linear: Linear,
    rotary: RotaryEmbedding,
    dtype: DType,
}

impl Qwen3BidirectionalModel {
    fn load(
        cfg: &VoyageConfig,
        vb: VarBuilder,
        device: &Device,
        dtype: DType,
    ) -> candle_core::Result<Self> {
        let model = vb.pp("model");
        let embed_tokens =
            candle_nn::embedding(cfg.vocab_size, cfg.hidden_size, model.pp("embed_tokens"))?;
        let mut layers = Vec::with_capacity(cfg.num_hidden_layers);
        let layers_vb = model.pp("layers");
        for i in 0..cfg.num_hidden_layers {
            layers.push(DecoderLayer::load(cfg, layers_vb.pp(i))?);
        }
        let norm = candle_nn::rms_norm(cfg.hidden_size, cfg.rms_norm_eps, model.pp("norm"))?;
        // Bias-free projection head 1024 -> 2048 (lives at top level, not under `model`).
        let linear = candle_nn::linear_no_bias(cfg.hidden_size, cfg.num_labels, vb.pp("linear"))?;
        let rotary = RotaryEmbedding::new(cfg, device, dtype)?;
        Ok(Self {
            embed_tokens,
            layers,
            norm,
            linear,
            rotary,
            dtype,
        })
    }

    /// `input_ids`/`attention_mask`: (b, seq) of u32 / f32. Returns per-token (b, seq, 2048).
    fn forward(&self, input_ids: &Tensor, attention_mask: &Tensor) -> candle_core::Result<Tensor> {
        let (_b, seq) = input_ids.dims2()?;
        let mut h = self.embed_tokens.forward(input_ids)?;
        let mask = self.bidirectional_mask(attention_mask, seq)?;
        for layer in &self.layers {
            h = layer.forward(&h, &mask, &self.rotary)?;
        }
        let h = self.norm.forward(&h)?;
        self.linear.forward(&h)
    }

    /// Additive bidirectional mask (b, 1, seq, seq): 0 where the key token is real,
    /// -inf where it is padding. No causal component.
    fn bidirectional_mask(
        &self,
        attention_mask: &Tensor,
        seq: usize,
    ) -> candle_core::Result<Tensor> {
        let (b, _) = attention_mask.dims2()?;
        // A large FINITE negative, not -inf: `(1 - 1) * -inf = NaN` would poison every
        // real key. With a finite value `0 * NEG = 0`, and `exp(NEG - max)` underflows
        // to 0, so masked keys still contribute nothing.
        const NEG: f64 = -1e30;
        // key-padding: (b, 1, 1, seq) broadcast over query positions.
        let key_mask = attention_mask.to_dtype(DType::F32)?;
        let additive = ((1.0 - key_mask)? * NEG)?; // real key -> 0, pad key -> -1e30
        additive
            .reshape((b, 1, 1, seq))?
            .broadcast_as((b, 1, seq, seq))?
            .to_dtype(self.dtype)
    }
}

/// Production embedder: voyageai/voyage-4-nano via Candle, MRL-truncated to 512.
pub struct VoyageEmbedder {
    model: Qwen3BidirectionalModel,
    tokenizer: Tokenizer,
    device: Device,
    label: String,
}

impl VoyageEmbedder {
    /// Load from a local model directory containing config.json, tokenizer.json, and
    /// model.safetensors.
    pub fn load(model_dir: &Path, device: Device, label: String) -> Result<Self, String> {
        let dtype = preferred_dtype(&device)?;
        let cfg: VoyageConfig = {
            let text = std::fs::read_to_string(model_dir.join("config.json"))
                .map_err(|err| format!("read config.json: {err}"))?;
            serde_json::from_str(&text).map_err(|err| format!("parse config.json: {err}"))?
        };
        if cfg.num_labels != NATIVE_DIM {
            return Err(format!(
                "voyage-4-nano config num_labels={} but expected projection head dim {NATIVE_DIM}",
                cfg.num_labels
            ));
        }
        let tokenizer = Tokenizer::from_file(model_dir.join("tokenizer.json"))
            .map_err(|err| format!("load tokenizer: {err}"))?;
        let weights = model_dir.join("model.safetensors");
        let label = format!("{label}:dtype={}", dtype_label(dtype));
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights], dtype, &device)
                .map_err(|err| format!("load safetensors: {err}"))?
        };
        let model = Qwen3BidirectionalModel::load(&cfg, vb, &device, dtype)
            .map_err(|err| format!("build model: {err}"))?;
        Ok(Self {
            model,
            tokenizer,
            device,
            label,
        })
    }

    fn embed_prefixed(&self, prefixed: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if prefixed.is_empty() {
            return Ok(Vec::new());
        }
        // Length-aware packing: sort by token length and greedily fill batches up to
        // the padded-token budget, so short chunks aren't padded up to a long one.
        let lens: Vec<usize> = prefixed
            .iter()
            .map(|text| {
                self.tokenizer
                    .encode(text.as_str(), true)
                    .map(|enc| enc.get_ids().len().clamp(1, MAX_SEQ_TOKENS))
                    .unwrap_or(1)
            })
            .collect();
        let mut order: Vec<usize> = (0..prefixed.len()).collect();
        order.sort_by_key(|&i| lens[i]);

        let mut out: Vec<Vec<f32>> = vec![Vec::new(); prefixed.len()];
        let mut batch: Vec<usize> = Vec::new();
        let mut batch_max = 0usize;
        for &i in &order {
            let new_max = batch_max.max(lens[i]);
            if !batch.is_empty() && (batch.len() + 1) * new_max > PADDED_TOKEN_BUDGET {
                self.run_batch(&batch, prefixed, &mut out)?;
                batch.clear();
                batch_max = 0;
            }
            batch.push(i);
            batch_max = batch_max.max(lens[i]);
        }
        if !batch.is_empty() {
            self.run_batch(&batch, prefixed, &mut out)?;
        }
        Ok(out)
    }

    /// Embed the texts at `idx` (one padded batch) and scatter results back to `out`.
    fn run_batch(
        &self,
        idx: &[usize],
        texts: &[String],
        out: &mut [Vec<f32>],
    ) -> Result<(), String> {
        let subset: Vec<String> = idx.iter().map(|&i| texts[i].clone()).collect();
        let vecs = self.embed_sub_batch(&subset)?;
        for (&i, vec) in idx.iter().zip(vecs) {
            out[i] = vec;
        }
        Ok(())
    }

    fn embed_sub_batch(&self, prefixed: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if prefixed.is_empty() {
            return Ok(Vec::new());
        }
        let encodings = self
            .tokenizer
            .encode_batch(prefixed.to_vec(), true)
            .map_err(|err| format!("tokenize: {err}"))?;
        let max_len = encodings
            .iter()
            .map(|e| e.get_ids().len().min(MAX_SEQ_TOKENS))
            .max()
            .unwrap_or(1)
            .max(1);
        let b = encodings.len();
        let token_lens: Vec<usize> = encodings
            .iter()
            .map(|encoding| encoding.get_ids().len().clamp(1, MAX_SEQ_TOKENS))
            .collect();
        let min_len = token_lens.iter().copied().min().unwrap_or(1);
        let avg_len = token_lens.iter().sum::<usize>() as f64 / token_lens.len() as f64;
        let padded_tokens = b * max_len;
        let mut ids = vec![0u32; b * max_len];
        let mut mask = vec![0f32; b * max_len];
        for (row, enc) in encodings.iter().enumerate() {
            let enc_ids = enc.get_ids();
            let take = enc_ids.len().min(max_len);
            for col in 0..take {
                ids[row * max_len + col] = enc_ids[col];
                mask[row * max_len + col] = 1.0;
            }
        }
        let input_ids = Tensor::from_vec(ids, (b, max_len), &self.device)
            .map_err(|err| format!("input_ids tensor: {err}"))?;
        let attention_mask = Tensor::from_vec(mask, (b, max_len), &self.device)
            .map_err(|err| format!("attention_mask tensor: {err}"))?;

        let start = Instant::now();
        let hidden = self
            .model
            .forward(&input_ids, &attention_mask)
            .map_err(|err| format!("forward: {err}"))?; // (b, seq, 2048)
        let pooled =
            masked_mean(&hidden, &attention_mask).map_err(|err| format!("mean pool: {err}"))?; // (b, 2048)
        let truncated = pooled
            .narrow(1, 0, VOYAGE_OUTPUT_DIM)
            .map_err(|err| format!("mrl truncate: {err}"))?;
        let normed = l2_normalize_rows(&truncated).map_err(|err| format!("normalize: {err}"))?;
        let vectors = normed
            .to_dtype(DType::F32)
            .and_then(|t| t.to_vec2::<f32>())
            .map_err(|err| format!("collect vectors: {err}"))?;
        if embed_profile_enabled() {
            let elapsed = start.elapsed();
            let seconds = elapsed.as_secs_f64();
            eprintln!(
                "[embed] batch_vectors={} min_seq={} avg_seq={:.1} max_seq={} padded_tokens={} elapsed_s={:.3} vectors_per_s={:.2} padded_tokens_per_s={:.0}",
                b,
                min_len,
                avg_len,
                max_len,
                padded_tokens,
                seconds,
                b as f64 / seconds,
                padded_tokens as f64 / seconds,
            );
        }
        Ok(vectors)
    }
}

impl Embedder for VoyageEmbedder {
    fn dim(&self) -> usize {
        VOYAGE_OUTPUT_DIM
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        let prefixed: Vec<String> = texts
            .iter()
            .map(|t| format!("{PASSAGE_PREFIX}{t}"))
            .collect();
        self.embed_prefixed(&prefixed)
    }

    fn embed_query(&self, text: &str) -> Result<Vec<f32>, String> {
        let prefixed = vec![format!("{QUERY_PREFIX}{text}")];
        let mut out = self.embed_prefixed(&prefixed)?;
        out.pop().ok_or_else(|| "empty query embedding".to_string())
    }

    fn count_tokens(&self, text: &str) -> usize {
        self.tokenizer
            .encode(text, false)
            .map(|enc| enc.get_ids().len())
            .unwrap_or(usize::MAX)
    }

    fn fingerprint(&self) -> String {
        super::engine::fingerprint_for(&self.label, VOYAGE_OUTPUT_DIM)
    }
}

/// Mean over non-pad tokens. `hidden`: (b, seq, d); `mask`: (b, seq).
fn masked_mean(hidden: &Tensor, mask: &Tensor) -> candle_core::Result<Tensor> {
    let mask = mask.to_dtype(hidden.dtype())?;
    let m = mask.unsqueeze(2)?; // (b, seq, 1)
    let summed = hidden.broadcast_mul(&m)?.sum(1)?; // (b, d)
    let counts = mask.sum(1)?.clamp(1f64, f64::INFINITY)?.unsqueeze(1)?; // (b, 1)
    summed.broadcast_div(&counts)
}

/// Row-wise L2 normalize a (b, d) tensor.
fn l2_normalize_rows(x: &Tensor) -> candle_core::Result<Tensor> {
    let norm = x
        .sqr()?
        .sum_keepdim(1)?
        .sqrt()?
        .clamp(1e-12, f64::INFINITY)?;
    x.broadcast_div(&norm)
}

fn dtype_label(dtype: DType) -> &'static str {
    match dtype {
        DType::F32 => "f32",
        DType::F16 => "f16",
        DType::BF16 => "bf16",
        _ => "other",
    }
}

/// Use the model's native bf16 by default. Set `BIFROST_EMBED_DTYPE` to override.
fn preferred_dtype(_device: &Device) -> Result<DType, String> {
    let Some(value) = std::env::var(EMBED_DTYPE_ENV).ok() else {
        return Ok(DType::BF16);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "f32" | "float32" => Ok(DType::F32),
        "f16" | "fp16" | "float16" => Ok(DType::F16),
        "bf16" | "bfloat16" => Ok(DType::BF16),
        "auto" | "native" => Ok(DType::BF16),
        other => Err(format!(
            "unsupported {EMBED_DTYPE_ENV}={other:?}; expected f32, f16, bf16, or auto"
        )),
    }
}
