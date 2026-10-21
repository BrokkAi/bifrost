//! Engine integration kept above the store and resolution layers.
pub mod epoch;
#[allow(dead_code, unused_imports)]
pub mod fact_reference_edges;
pub mod go_graph;
mod parsed_blob;
pub mod rust_graph;
pub use parsed_blob::AnalyzerStoreEngineExt;
