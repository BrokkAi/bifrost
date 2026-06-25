//! Vector compression for the searchable composed vectors.
//!
//! Composed vectors are stored as 8-bit rotational-quantization codes (fastrq,
//! RaBitQ-style) instead of raw f32: ~4x smaller blobs and a branch-free `u8` scan
//! that stays memory-bound. The quantizer is training-free and uses a fixed default
//! rotation seed, so every process builds byte-identical codes — no persistence
//! needed. Vectors are unit-normalized, so `Metric::Dot` distance is the negative
//! inner product; we flip it back to a dot estimate (higher = more similar) to keep
//! the existing ranking semantics.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use fastrq::{Bits, Metric, QueryDistancer, RotationalQuantizer, RqCode};

/// Process-wide quantizers, one per input dimension (only the embedder's dim — 512
/// — occurs in practice). Leaked to `'static` so codes and query distancers can
/// borrow them across the index lifetime; there is exactly one per dim.
fn quantizer(dim: usize) -> &'static RotationalQuantizer {
    static CACHE: OnceLock<RwLock<HashMap<usize, &'static RotationalQuantizer>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(q) = cache.read().expect("quant cache poisoned").get(&dim) {
        return q;
    }
    let mut writer = cache.write().expect("quant cache poisoned");
    writer.entry(dim).or_insert_with(|| {
        Box::leak(Box::new(RotationalQuantizer::new(dim, Bits::Eight, Metric::Dot)))
    })
}

/// Encode a unit vector to fastrq code bytes for storage.
pub fn encode_vector(vector: &[f32]) -> Vec<u8> {
    quantizer(vector.len()).encode(vector).to_bytes()
}

/// Decode stored code bytes back to an approximate f32 vector — used to re-compose
/// child+parent component vectors. Lossy (8-bit), so composing then re-encoding
/// stacks a second small quantization error; negligible for ranking.
pub fn decode_vector(code_bytes: &[u8]) -> Result<Vec<f32>, String> {
    let code = RqCode::from_bytes(code_bytes).map_err(|err| format!("rq decode: {err}"))?;
    Ok(quantizer(code.dimension()).decode(&code))
}

/// A query scorer: encodes the query once, then estimates the dot product against
/// many stored codes. `Send + Sync`, so the scan can score batches in parallel.
pub struct CodeScorer {
    distancer: QueryDistancer<'static>,
}

/// Build a scorer for `query` (the raw f32 query vector).
pub fn query_scorer(query: &[f32]) -> CodeScorer {
    CodeScorer {
        distancer: quantizer(query.len()).query_distancer(query),
    }
}

impl CodeScorer {
    /// Estimated dot product of the query against a stored code (higher = more
    /// similar). `Metric::Dot` distance is `-dot`, so we negate it back.
    pub fn score(&self, code_bytes: &[u8]) -> Result<f32, String> {
        let code = RqCode::from_bytes(code_bytes).map_err(|err| format!("rq decode: {err}"))?;
        self.distancer
            .distance(&code)
            .map(|dist| -dist)
            .map_err(|err| format!("rq distance: {err}"))
    }
}
