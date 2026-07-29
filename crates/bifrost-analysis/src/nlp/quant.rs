//! Vector compression for the searchable composed vectors.
//!
//! Composed vectors are stored as 8-bit rotational-quantization codes (fastrq,
//! RaBitQ-style) instead of raw f32: ~4x smaller blobs and a branch-free `u8` scan
//! that stays memory-bound. The quantizer is training-free and uses a fixed default
//! rotation seed, so every process builds byte-identical codes — no persistence
//! needed (fastrq pins this with a golden-bytes test). Vectors are unit-normalized,
//! so `Metric::Dot` distance is the negative inner product; we flip it back to a
//! dot estimate (higher = more similar) to keep the existing ranking semantics.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use fastrq::{Bits, Metric, QueryDistancer, RotationalQuantizer};

/// Process-wide quantizers, one per input dimension (only the embedder's dim — 512
/// — occurs in practice). Shared via `Arc`; building a rotation is cheap but not
/// free, so we still cache rather than rebuild per call.
fn quantizer(dim: usize) -> Arc<RotationalQuantizer> {
    static CACHE: OnceLock<RwLock<HashMap<usize, Arc<RotationalQuantizer>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(q) = cache.read().expect("quant cache poisoned").get(&dim) {
        return Arc::clone(q);
    }
    let mut writer = cache.write().expect("quant cache poisoned");
    Arc::clone(
        writer
            .entry(dim)
            .or_insert_with(|| Arc::new(RotationalQuantizer::new(dim, Bits::Eight, Metric::Dot))),
    )
}

/// Encode a unit vector to fastrq flat code bytes for storage.
pub fn encode_vector(vector: &[f32]) -> Vec<u8> {
    quantizer(vector.len()).encode_to_bytes(vector)
}

/// Decode stored code bytes back to an approximate f32 vector — used to re-compose
/// child+parent component vectors. Lossy (8-bit), so composing then re-encoding
/// stacks a second small quantization error; negligible for ranking.
pub fn decode_vector(code_bytes: &[u8]) -> Result<Vec<f32>, String> {
    // Flat rq8 layout: 16 metadata bytes then one code byte per rotated dim.
    let dim = code_bytes.len().saturating_sub(fastrq::RQ_METADATA_SIZE);
    quantizer(dim)
        .decode_bytes(code_bytes)
        .map_err(|err| format!("rq decode: {err}"))
}

/// A query scorer: encodes the query once, then estimates the dot product against
/// many stored codes. `Send + Sync`, so the scan can score batches in parallel.
pub struct CodeScorer {
    distancer: QueryDistancer,
}

/// Build a scorer for `query` (the raw f32 query vector).
pub fn query_scorer(query: &[f32]) -> CodeScorer {
    CodeScorer {
        distancer: quantizer(query.len()).query_distancer(query),
    }
}

impl CodeScorer {
    /// Estimated dot product of the query against a stored flat code (higher =
    /// more similar), scored allocation-free straight from the stored bytes.
    /// `Metric::Dot` distance is `-dot`, so we negate it back.
    pub fn score(&self, code_bytes: &[u8]) -> Result<f32, String> {
        self.distancer
            .distance_bytes(code_bytes)
            .map(|dist| -dist)
            .map_err(|err| format!("rq distance: {err}"))
    }
}
