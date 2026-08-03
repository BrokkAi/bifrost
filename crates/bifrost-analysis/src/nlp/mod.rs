//! Semantic code search: parent-averaged function embeddings + grounded-strings
//! BM25 + git co-edit relevance, returned as independent retrieval signals.
//! Reranking happens downstream, outside this crate.
//!
//! The design (and every tuned constant below) is ported from the brokkbench
//! localizer prototype; see `analysis/{bm25,coedit-reranker}/REPORT.md`
//! there for the sweeps that selected these values.

pub mod active_index;
pub mod bm25;
pub mod chunker;
pub mod engine;
pub mod gitcache;
pub mod indexer;
pub mod keys;
pub mod materialize;
pub mod metrics;
pub mod quant;
pub mod query;
pub mod store;
pub mod voyage_sidecar;

/// Whether `semantic_search` should be offered. The voyage-4-nano embedder (PyTorch
/// sidecar) is fast on a CUDA or Metal accelerator; on CPU-only hosts the tool is hidden
/// unless the operator opts in with `--force-semantic-cpu` (`BIFROST_FORCE_SEMANTIC_CPU=1`).
pub fn semantic_search_available() -> bool {
    force_semantic_cpu() || engine::accelerator_available()
}

/// Operator override to run the embedder on CPU where no accelerator exists.
pub fn force_semantic_cpu() -> bool {
    matches!(
        std::env::var("BIFROST_FORCE_SEMANTIC_CPU").as_deref(),
        Ok("1") | Ok("true") | Ok("on") | Ok("enabled")
    )
}

/// Reciprocal-rank smoothing constant for the positional co-edit score.
pub const RRF_K: f64 = 30.0;

/// Recency half-life (commits) passed to most_relevant_files.
pub const COEDIT_HALF_LIFE: f64 = 250.0;

/// Cap on distinct BM25 query tokens.
pub const MAX_QUERY_TOKENS: usize = 256;

/// Versioned contracts shared with the prototype's vector cache key recipe.
pub const COMPONENT_CONTRACT_VERSION: &str = "component_v1";
pub const REPRESENTATION_KIND: &str = "parent_avg_v1";

/// Bump when the BM25 tokenizer changes; stored in the index meta table.
pub const BM25_TOKENIZER_VERSION: &str = "code-subtoken-v1";

/// Bump when chunk extraction or parent-text derivation changes.
pub const CHUNKER_VERSION: &str = "chunker_v1";
